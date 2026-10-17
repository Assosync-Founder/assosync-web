# Module Authentication

Ce dossier contient le noyau d’authentification serveur d’Assosync Account.

Il ne rend pas les formulaires de connexion des produits : il reçoit une preuve
d’identité Firebase, applique la politique de sécurité d’Assosync, vérifie la
confiance de l’appareil, crée les sessions et, pour le Web, réalise le pont SSO
vers Calendis ou Collectineo.

> Les secrets, les tokens Firebase, les cookies de session, les codes email et
> les identifiants de passkey ne doivent jamais être journalisés, affichés ou
> transmis à un composant client autrement que par les flux explicitement
> décrits ici.

## Sommaire

- [Rôle et périmètre](#rôle-et-périmètre)
- [Vocabulaire](#vocabulaire)
- [Architecture](#architecture)
- [Configuration](#configuration)
- [Cookies et données persistées](#cookies-et-données-persistées)
- [Scripts Lua Redis et atomicité](#scripts-lua-redis-et-atomicité)
- [Modes de connexion](#modes-de-connexion)
- [Vérification d’un nouvel appareil](#vérification-dun-nouvel-appareil)
- [Sessions et déconnexion](#sessions-et-déconnexion)
- [SSO Web entre les produits](#sso-web-entre-les-produits)
- [Passkeys](#passkeys)
- [Approbation mobile](#approbation-mobile)
- [Alertes et audit de sécurité](#alertes-et-audit-de-sécurité)
- [Référence des routes HTTP](#référence-des-routes-http)
- [Référence fichier par fichier](#référence-fichier-par-fichier)
- [Diagnostic](#diagnostic)
- [Vérifications avant mise en production](#vérifications-avant-mise-en-production)

## Rôle et périmètre

Le module couvre les responsabilités suivantes :

1. vérifier une identité Firebase fraîche et non révoquée ;
2. associer cette identité à un navigateur déjà approuvé ou à un nouvel appareil ;
3. confirmer un nouvel appareil par code email ou, lorsque les applications
   mobiles existent, par approbation mobile ;
4. créer deux sessions complémentaires : une session Firebase et une session
   applicative révocable ;
5. émettre et vérifier les cookies HTTP-only ;
6. fournir l’authentification par passkey WebAuthn ;
7. terminer un SSO Web confidentiel vers Calendis ou Collectineo ;
8. permettre à l’utilisateur de voir et révoquer appareils, sessions et passkeys ;
9. enregistrer les événements de sécurité et envoyer des emails d’alerte.

Le module ne remplace pas Firebase Authentication : Firebase valide le mot de
passe, Google, Microsoft ou tout autre fournisseur. Assosync décide ensuite si
le navigateur peut créer une session pour le produit demandé.

## Vocabulaire

| Terme | Signification |
| --- | --- |
| **Identité Firebase** | Utilisateur Firebase validé par un ID token récent. |
| **Appareil** | Navigateur reconnu par un cookie opaque, propre à un utilisateur et à un produit. |
| **Vérification** | Objet temporaire Redis qui attend un code email ou une décision mobile. |
| **Session Firebase** | Cookie signé Firebase, vérifié avec révocation. |
| **Session applicative** | Session Assosync stockée dans Firestore, révocable indépendamment de Firebase. |
| **Autorisation Web** | État temporaire Redis du SSO : produit cible, PKCE, identité et liaison navigateur. |
| **Grant Web** | État Redis consommable une fois par le callback serveur du produit. |
| **Passkey** | Identifiant WebAuthn local ou synchronisé, protégé par Touch ID, Windows Hello, PIN ou clé de sécurité. |
| **Ticket flash** | Secret opaque Redis, consommé une fois par un produit afin de déposer un message dans son cookie flash. |

## Architecture

```text
Navigateur
    │
    ├── Firebase Auth : mot de passe, OAuth ou custom token passkey
    │       └── ID token Firebase
    │
    └── Account API
            ├── vérifie l'identité Firebase
            ├── reconnaît ou crée un appareil
            ├── demande une vérification si nécessaire
            ├── crée les sessions Firebase + Assosync
            └── finalise éventuellement le SSO du produit

Firestore : appareils, sessions, passkeys, installations mobiles, événements
Redis     : vérifications courtes, limites, challenges WebAuthn, SSO, flash
Firebase  : utilisateurs, ID tokens, custom tokens, session cookies
Resend    : codes de vérification et alertes de sécurité
FCM       : approbations mobiles, lorsque les applications mobiles sont prêtes
```

Le navigateur ne reçoit jamais :

- le secret client SSO d’un produit ;
- les hashes de tokens ;
- les clés publiques WebAuthn d’autres utilisateurs ;
- les codes email stockés ou leurs hashes ;
- un cookie de session lisible par JavaScript.

## Configuration

Le fichier [`src/config/auth.ts`](../../config/auth.ts) est la source de vérité
des durées et des clients reconnus.

### Cookies

`cookieNames` construit les noms à partir de `@assosync/contracts/auth/cookies`.
En production, le préfixe `__Host-` est appliqué. Il impose un cookie sécurisé,
sans attribut `Domain`, avec le chemin `/`.

| Cookie | Usage | Durée habituelle |
| --- | --- | --- |
| `session` | Cookie de session Firebase. | Durée de session. |
| `connection` | Token de session applicative Assosync. | Durée de session. |
| `device` | Secret opaque du navigateur de confiance. | Durée de confiance appareil. |
| `deviceVerification` | Secret temporaire liant le navigateur à une vérification. | 10 minutes. |
| `webAuthorization` | Secret temporaire liant le navigateur au SSO Account. | 10 minutes. |
| `approval` | Réservé au parcours d’approbation mobile. | Temporaire. |

Les cookies sont écrits par `http/auth-cookies.ts` via les descripteurs de
`cookies/auth-cookie.ts`. Ils sont `HttpOnly`, `SameSite=Lax`, limités à `/` et
`Secure` hors développement.

### Appareils, sessions et événements

| Bloc | Paramètres | Signification |
| --- | --- | --- |
| `device` | `pendingLifetimeMs`, `trustedLifetimeMs` | Un appareil en attente est éphémère ; un appareil vérifié est actuellement reconnu pendant un an. |
| `deviceVerification` | durée, tentatives, renvois, cooldown, pénalités | Politique des codes email et défense contre l’abus. |
| `session` | `lifetimeMs`, `maxAuthenticationAgeMs` | Durée maximale des cookies et fraîcheur exigée pour ajouter une passkey. |
| `securityEvent` | `retentionMs` | Date d’expiration Firestore des événements d’audit. |

Les pénalités email sont progressives : 15 minutes, 1 heure, 6 heures puis 24
heures. La clé Redis de pénalité peut vivre plus longtemps que le blocage
actuel : elle conserve le niveau afin qu’une répétition après le premier délai
passe au niveau suivant. `blockedUntil` est la source de vérité du délai actif.

### Passkeys

`passkey` contient :

- `rpName` : nom affiché par le navigateur ;
- `rpId` : domaine WebAuthn, `account.assosync.fr` en production ;
- `expectedOrigin` : origine exacte autorisée pour les réponses WebAuthn ;
- `challengeLifetimeMs` : cinq minutes pour s’authentifier ou enregistrer une
  passkey.

Le `rpId` doit correspondre au domaine réellement utilisé. Une passkey créée
pour `account.localhost` ne peut pas être utilisée sur le domaine de production.
La synchronisation entre Chrome et Safari dépend du gestionnaire de passkeys
utilisé par l’utilisateur ; elle n’est pas garantie par Assosync.

### SSO Web

`webSso` enregistre pour chaque client :

- son identifiant (`calendis` ou `collectineo`) ;
- sa page de connexion ;
- son endpoint de relais flash ;
- les URI de callback exactes autorisées ;
- son secret serveur confidentiel.

Le secret doit contenir au moins 32 octets, ne doit exister que dans les
variables privées d’Assosync, Calendis et Collectineo, et ne doit jamais être
préfixé par `NEXT_PUBLIC_`.

Les URI de callback sont exactes : une différence de protocole, hôte, port ou
chemin est rejetée. En développement, Calendis utilise
`http://app.localhost:3001/api/auth/callback` et Collectineo le port `3002`.

### Applications et hôtes

`applications` associe les hôtes connus à une application. Cette association
est utilisée lors de la vérification des sessions et des appareils. Les routes
Account imposent aussi `account.assosync.fr` ou `account.localhost` avec
`assertAccountHostname`.

En production, le reverse proxy doit supprimer puis reconstruire les en-têtes
`X-Forwarded-Host` et `X-Forwarded-Proto`. Le module s’en sert pour reconstruire
l’origine ; laisser un client les injecter directement rendrait toute politique
fondée sur l’hôte moins fiable.

## Cookies et données persistées

### Firestore

Les documents permanents sont sous `account/{userId}` :

| Sous-collection | Contenu | Expiration / révocation |
| --- | --- | --- |
| `devices` | Métadonnées navigateur, hash du token, état, dates. | Appareil expiré, révoqué ou en attente nettoyé selon la politique TTL. |
| `sessions` | Hash du token de session, appareil, produit, dates. | Expiré ou révoqué. |
| `passkeys` | Clé publique WebAuthn, compteur, métadonnées sûres. | Supprimée par l’utilisateur. |
| `mobileInstallations` | Installation mobile et token FCM serveur. | Désactivable. |
| `securityEvents` | Événements sans secret, pour support/audit. | `expires` selon `securityEvent.retentionMs`. |

Les repositories relisent et valident leurs propres documents : Firestore est
traité comme une frontière externe, pas comme une source implicitement sûre.

### Redis

Redis contient uniquement des états courts :

- vérifications email/mobile ;
- réservations et pénalités de rate limit ;
- challenges WebAuthn ;
- tickets d’identité, autorisations et grants SSO ;
- tickets flash à usage unique.

Les états sensibles sont liés à un hash du token navigateur et possèdent une
TTL. Les objets à usage unique sont lus et supprimés atomiquement (`GETDEL` ou
scripts Lua). Une clé visible dans le Data Browser jusqu’à sa TTL n’est pas une
session utilisable sans son secret aléatoire correspondant.

## Scripts Lua Redis et atomicité

### Pourquoi des scripts Lua ?

Redis exécute une commande simple de façon atomique, mais un parcours Auth a
souvent besoin de plusieurs opérations qui doivent former **une seule
transition**. Par exemple, vérifier un code demande simultanément de lire la
vérification, vérifier sa liaison au navigateur, comparer le hash, incrémenter
le compteur d’échecs et éventuellement verrouiller l’objet.

Faire cela en TypeScript avec plusieurs appels Redis créerait une fenêtre de
course : deux requêtes parallèles pourraient toutes les deux lire `4` essais,
considérer qu’un dernier essai est possible, puis écrire chacune une valeur
incohérente. Un script Lua est exécuté de manière séquentielle par Redis :
aucune autre commande ne s’intercale entre son premier `GET` et son dernier
`SET` ou `DEL`.

Les scripts sont envoyés par le repository concerné. Ils ne reçoivent que des
clés (`KEYS`) et des valeurs validées (`ARGV`) ; ils ne font ni appel réseau ni
log. Le TypeScript interprète ensuite leurs réponses JSON et les convertit en
types métier.

```text
Route HTTP
  → Service métier : valide la règle métier et prépare les hashes
  → Repository Redis : exécute le script Lua
  → Lua : lit, valide, modifie ou supprime l’état en une transition atomique
  → Repository : valide la réponse Redis
  → Service : décide de la session, de l’email, du flash ou de l’erreur publique
```

### Principes communs des scripts

| Principe | Raison |
| --- | --- |
| Toutes les clés sont calculées côté serveur. | Le navigateur ne choisit jamais une clé Redis sensible. |
| Les secrets bruts sont hashés avant comparaison. | Un export Redis ne permet pas de rejouer un cookie ou un token. |
| L’utilisateur, le produit, l’appareil et le token navigateur sont comparés ensemble. | Un identifiant de vérification seul ne suffit pas à agir sur une demande. |
| Les TTL sont conservées avec `KEEPTTL` ou explicitement recalculées. | Une écriture ne doit jamais rendre un état temporaire permanent par accident. |
| Les opérations à usage unique font `DEL` dans le script. | Deux requêtes concurrentes ne peuvent pas consommer le même ticket/grant. |
| Une réponse invalide est traitée comme absente. | La donnée Redis est une frontière non fiable. |
| Les scripts restent courts. | Un script Lua long bloque Redis pendant son exécution. |

Un `return 0`, `return nil` ou `outcome = 'not_found'` n’indique pas
nécessairement qu’une clé n’existe pas : il peut volontairement masquer une
liaison incorrecte, un token navigateur différent ou un état déjà consommé.
Cela réduit les informations exploitables par un attaquant.

### Vérifications d’appareil : `verification-scripts.ts`

Ce fichier contient la machine à états des vérifications temporaires. Une
vérification suit principalement ce cycle :

```text
pending
  ├─ code email correct / approbation mobile → approved
  ├─ refus mobile                         → rejected
  ├─ finalisation de l’appareil           → finalizing → consumed
  ├─ trop de codes erronés                → locked implicitement par compteur
  └─ TTL ou annulation                    → supprimée
```

`locked` est rapporté par le résultat de tentative lorsque `failedAttempts`
atteint `maxAttempts`. L’objet reste temporaire dans Redis jusqu’à sa TTL afin
de conserver l’état et empêcher de recommencer avec le même identifiant.

| Script | Transition atomique | Détails importants |
| --- | --- | --- |
| `createVerificationScript` | Crée la vérification et, pour le mobile, son index d’approbation. | Refuse toute collision et applique la même TTL à l’objet et à l’index. |
| `attemptEmailCodeScript` | Valide le code email ou incrémente les essais. | Vérifie utilisateur, produit, token navigateur, mode et expiration avant le hash du code. Le compteur et le statut sont écrits avec `KEEPTTL`. |
| `resendEmailCodeScript` | Remplace le code et prend un snapshot de rollback. | Vérifie cooldown et limite, conserve l’ancien objet dans une seconde clé avec sa TTL restante, puis réinitialise le compteur pour le nouveau code. |
| `completeEmailCodeResendScript` | Valide la livraison réussie. | Supprime uniquement le snapshot de rollback si la vérification courante est bien celle qui vient d’être envoyée. |
| `rollbackEmailCodeResendScript` | Restaure le code précédent. | Utilisé si Resend échoue après la réservation ; évite de laisser l’utilisateur avec un code qu’il n’a jamais reçu. |
| `cancelEmailVerificationScript` | Supprime une vérification email encore annulable. | Exige les quatre liaisons : utilisateur, produit, appareil et navigateur. |
| `approveMobileScript` | Passe une demande mobile de `pending` à `approved`. | Vérifie l’index d’approbation, le hash du secret mobile et l’expiration. Répéter une approbation déjà acceptée est idempotent. |
| `resolveMobileApprovalScript` | Lit le détail sûr pour le BottomSheet mobile. | Exige le secret mobile ; accepte seulement les états affichables. |
| `resolveBrowserMobileVerificationScript` | Lit l’état pour le navigateur en attente. | Exige la liaison navigateur, produit et appareil. |
| `rejectMobileScript` | Passe une demande de `pending` à `rejected`. | Idempotent pour un second refus ; les autres états ne peuvent pas être écrasés. |
| `beginFinalizationScript` | Réserve la finalisation après approbation. | Passe à `finalizing` puis conserve assez longtemps l’objet pour récupérer d’un échec partiel Firestore/session. |
| `completeFinalizationScript` | Marque la vérification consommée. | Idempotent : une répétition ne recrée jamais de session et prolonge seulement la TTL de récupération. |

La finalisation est séparée en deux scripts parce qu’elle traverse Redis et
Firestore. Redis ne peut pas englober une transaction Firestore. Le statut
`finalizing`, puis `consumed`, évite qu’un navigateur concurrent crée plusieurs
sessions pendant cette fenêtre. Si la finalisation est répétée après une panne,
les opérations métier peuvent reprendre de façon idempotente.

### Limitation progressive : `verification-rate-limit-scripts.ts`

Ces scripts protègent l’envoi d’emails avant que le fournisseur email soit
sollicité. Les clés principales sont conceptuellement :

```text
auth:email-verification-rate-limit:{userId}:{applicationId}:penalty
auth:email-verification-rate-limit:{userId}:{applicationId}:initial-window
```

Le nom exact et les hashes éventuels sont construits par
`verification-rate-limit-repository.ts`; ne pas reconstruire ces clés dans une
route ou une vue.

| Script | Rôle | Résultat |
| --- | --- | --- |
| `checkEmailVerificationLimitScript` | Vérifie `blockedUntil`. | Autorise ou retourne le délai restant et le niveau actif. |
| `reserveInitialVerificationEmailScript` | Compte les emails initiaux dans une fenêtre fixe. | Incrémente avec `INCR`, installe la TTL seulement au premier incrément, puis signale qu’une pénalité est nécessaire au-delà de la limite. |
| `applyEmailVerificationPenaltyScript` | Applique le niveau suivant. | Réinitialise le niveau après `penaltyResetMs`, plafonne au niveau 4 et stocke `level`, `blockedUntil`, `lastPenaltyAt`. |

La TTL de la clé `penalty` est `penaltyResetMs + durée du blocage`. Elle peut
donc être supérieure à `blockedUntil` : c’est intentionnel. `blockedUntil`
détermine quand la connexion peut reprendre ; la TTL conserve le niveau afin
qu’un nouvel abus après le premier délai passe à 1 heure, puis 6 heures et 24
heures, plutôt que de revenir immédiatement à 15 minutes.

### SSO Web et passkeys : `authorization-scripts.ts`

Les scripts SSO protègent l’échange de preuve entre Account et les serveurs
Calendis/Collectineo. Ils évitent surtout les rejouements et les échanges
partiellement terminés.

| Script | Transition atomique | Protection apportée |
| --- | --- | --- |
| `consumeWebAuthorizationIdentityTicketScript` | Lit puis supprime le ticket d’identité. | Le ticket Firebase ou passkey ne peut initialiser qu’une seule autorisation Account. |
| `completeWebAuthorizationScript` | Supprime l’autorisation navigateur et crée le grant court. | Vérifie le hash du navigateur, l’expiration et l’absence de grant déjà existant avant de basculer l’état. |
| `consumeWebAuthorizationGrantScript` | Vérifie puis supprime le grant. | Le callback produit doit fournir le bon client, callback, PKCE challenge et `state`; un second échange échoue. |
| `bindWebAuthorizationPasskeyUserScript` | Attache l’utilisateur découvert par WebAuthn. | Accepte uniquement une identité passkey initialement vide et conserve la TTL du SSO. |
| `bindWebAuthorizationIdentityTokenScript` | Attache ensuite l’ID token Firebase créé depuis le custom token. | Refuse une seconde liaison et vérifie que l’utilisateur correspond à celui de la passkey. |

Dans Lua, `cjson.null` doit être utilisé pour préserver une valeur `null` dans
une structure JSON. Une valeur JavaScript `undefined` n’existe pas en JSON et
peut disparaître lors de la sérialisation. C’est particulièrement important
pour l’identité temporaire passkey : elle évolue de
`{ userId: null, idToken: null }` vers un utilisateur puis vers un ID token.
Les parseurs TypeScript acceptent de façon défensive certaines anciennes clés
temporaires, mais tout nouvel état doit écrire `null` explicitement.

### Comment déboguer sans fragiliser Redis

1. Relever l’heure, le `requestId`, l’application et l’étape qui échoue.
2. Lire la TTL et les champs non secrets dans Upstash Data Browser.
3. Ne jamais copier le token brut, le code email, le ticket Web ou le
   `browserTokenHash` dans une issue publique.
4. Vérifier si la clé a été consommée : une absence après un succès est normale
   pour un ticket, un grant ou un challenge à usage unique.
5. Pour une vérification, comparer seulement les états (`pending`, `approved`,
   `finalizing`, `consumed`, `rejected`), `expiresAt`, le nombre d’essais et les
   compteurs de renvoi.
6. En développement, privilégier une nouvelle tentative ou attendre la TTL ; ne
   modifier manuellement une clé que pour un scénario de test explicitement
   isolé.

Un script Lua ne doit jamais être exécuté depuis le navigateur. Les scripts sont
des détails d’infrastructure du serveur et les routes HTTP restent les seules
frontières publiques du module.

## Modes de connexion

### Email et mot de passe

1. Le formulaire du produit appelle Firebase Auth côté navigateur avec
   `signInWithEmailAndPassword`.
2. Firebase retourne un ID token.
3. Le serveur du produit appelle Account `/api/auth/web/identity` avec son
   secret client, le token, PKCE et son URI de callback.
4. Account vérifie le token Firebase avec vérification de révocation.
5. Le navigateur est redirigé vers Account `/api/auth/web/authorize`, puis
   `/api/auth/web/continue`.
6. Account reconnaît l’appareil ou lance une vérification.
7. Une fois l’appareil approuvé, le callback serveur du produit échange le grant
   contre les cookies de session de ce produit.

Le mot de passe n’est jamais reçu ni validé par ce dossier : Firebase Auth en
est le seul responsable.

### OAuth Google ou Microsoft

Le module est volontairement agnostique du fournisseur. Un parcours OAuth doit
se terminer côté Firebase Auth, par exemple avec `signInWithPopup` ou
`signInWithRedirect`, puis récupérer un ID token Firebase. À partir de là, le
flux est **strictement le même** que pour email/mot de passe :

```text
OAuth provider → Firebase Auth → Firebase ID token → /web/identity → SSO
```

L’ajout d’un bouton Google ou Microsoft dans un produit ne contourne donc ni la
confiance de l’appareil, ni les sessions Assosync. Le fournisseur OAuth ne rend
pas un nouvel appareil automatiquement fiable.

### Passkey, Touch ID et Windows Hello

La passkey authentifie un utilisateur sans demander son email, mais elle ne
rend jamais un appareil de confiance à elle seule.

1. Le serveur du produit crée une transaction PKCE et appelle
   `/api/auth/passkeys/web/identity` avec son secret client.
2. Le navigateur arrive sur Account `/passkey?authorization=…`.
3. `PasskeyAuthenticationView` demande les options à
   `/api/auth/passkeys/options`.
4. Le navigateur lance la cérémonie `@simplewebauthn/browser` : Touch ID,
   Windows Hello, PIN, gestionnaire de passkeys ou clé de sécurité.
5. `/api/auth/passkeys/verify` vérifie la réponse, l’origine, le RP ID,
   l’user verification et le compteur. Il crée un custom token Firebase.
6. Le navigateur obtient un ID token Firebase à partir de ce custom token.
7. `/api/auth/passkeys/bind` lie ce token à l’autorisation Web.
8. `/api/auth/web/continue` reprend le même contrôle de confiance d’appareil
   que le mot de passe.

Si la cérémonie échoue ou est annulée, la page Account redirige vers le produit
via un ticket flash opaque. Le ticket vit au plus cinq minutes, soit la durée
du challenge WebAuthn ; il est supprimé dès sa consommation.

### Enregistrement d’une passkey

L’utilisateur déjà connecté à Account ouvre `/security` :

1. `POST /api/account/passkeys/registration/options` exige une session Account
   de moins de `maxAuthenticationAgeMs`.
2. L’API génère les options de création avec attestation `none`, authenticator
   de plateforme préféré, resident key et user verification obligatoires.
3. `POST /api/account/passkeys/registration/verify` consomme le challenge,
   vérifie la réponse puis stocke uniquement la clé publique et les métadonnées.
4. Le nom par défaut est détecté avec Bowser : `Clé d’accès Chrome`,
   `Clé d’accès Safari`, etc.

Les passkeys se listent, se renomment et se suppriment avec les routes
`/api/account/passkeys`.

## Vérification d’un nouvel appareil

### Décision de confiance

Après une identité Firebase valide, `DeviceService.prepareLogin` cherche le
cookie `device` pour le même utilisateur.

- Aucun cookie ou cookie inconnu, expiré, révoqué : création d’un appareil
  `pending` et vérification obligatoire.
- Cookie connu, appareil `verified`, non expiré et appartenant à l’utilisateur :
  session créée immédiatement.
- Cookie associé à un autre produit : nouvel appareil pour ce produit.

Le token brut reste dans le cookie HTTP-only. Seul son SHA-256 est stocké dans
Firestore. Supprimer le cookie force une nouvelle vérification, mais ne révoque
pas le document device existant : c’est voulu, afin que les autres sessions
puissent rester gérées depuis les paramètres de sécurité.

### Code email

1. `VerificationService.startEmail` vérifie l’appareil pending, réserve le rate
   limit et crée un code à six chiffres.
2. Redis ne conserve qu’un hash HMAC du code et un hash du token navigateur.
3. `VerificationEmailService` envoie le code avec la marque du produit.
4. `POST /api/auth/confirm-device` vérifie le code, verrouille après trop
   d’essais, puis vérifie l’appareil et crée la session.
5. Après preuve du code, `AuthenticationService.completeEmail` appelle Firebase
   Admin pour définir `emailVerified: true` seulement si ce n’est pas déjà le
   cas.

Le code est donc aussi la preuve de contrôle de l’adresse email. Il n’y a pas
de prérequis `emailVerified` avant de démarrer une connexion.

### Renvoi, annulation et pénalités

Les routes de gestion sont :

- `POST /api/auth/verification/email/resend` ;
- `POST /api/auth/verification/cancel`.

Le renvoi remplace le code précédent, impose un cooldown et un nombre maximal
de renvois. Une fois la limite atteinte, Redis applique une pénalité progressive.
Un échec de livraison restaure le code précédent lorsque cela est possible afin
de ne pas bloquer un utilisateur à cause du fournisseur email.

Un code erroné ne doit jamais indiquer lequel des identifiants, du code ou de
l’état de vérification est invalide à un attaquant. Les réponses publiques sont
génériques ; les logs serveur comportent un `requestId`.

### Approbation mobile

Lorsque des installations mobiles actives existent :

1. `MobileApprovalService.start` crée une vérification mobile et envoie une
   notification FCM à toutes les installations actives ;
2. l’application mobile récupère les détails sûrs via
   `GET /api/auth/mobile/approvals/{verificationId}` ;
3. elle accepte ou refuse avec `POST` sur la même route ;
4. le navigateur interroge `POST /api/auth/confirm-mobile` pour terminer après
   acceptation.

En l’absence d’installation livrable, le service annule la demande mobile et
retombe sur le code email. Le mobile est un mode d’approbation, pas un moyen de
contourner le contrôle de l’appareil.

## Sessions et déconnexion

Une connexion validée crée deux preuves qui doivent toujours être présentes :

1. le cookie Firebase, signé et révocable côté Firebase ;
2. le token de session applicative, dont le hash est dans Firestore.

`SessionService.verify` vérifie Firebase avec révocation, retrouve la session
applicative pour le bon produit, contrôle ses dates, puis contrôle que son
appareil est toujours `verified`.

Révoquer une session ou un appareil est donc immédiat pour les requêtes
suivantes. La déconnexion d’un produit enlève ses cookies ; elle ne supprime pas
automatiquement la session Account ni les sessions des autres produits. Cela
permet un choix explicite : se déconnecter d’un produit, d’Account, d’un seul
appareil, ou de toutes les sessions.

## SSO Web entre les produits

### Parcours nominal

```text
Calendis /login
  → Firebase Auth côté navigateur
  → Calendis serveur : /api/auth/web/identity sur Account
  → Account /api/auth/web/authorize
  → Account /api/auth/web/continue
      ├─ appareil connu : callback produit
      └─ nouvel appareil : /confirm-device → code email / mobile
  → Account crée un grant court
  → Calendis /api/auth/callback échange le grant
  → cookies Calendis → route authentifiée
```

Le callback ne transporte pas de code dans l’URL. Le grant est côté Redis et le
callback produit fournit simultanément son secret client, l’état, le verifier
PKCE et l’URI exacte attendue. Le grant est consommé une seule fois.

### Session Account parallèle

Lors d’une finalisation SSO réussie, Account crée aussi sa propre session. Ainsi
`account.assosync.fr/security` peut fonctionner après une connexion depuis
Calendis. Cette session reste indépendante des cookies Calendis : supprimer les
cookies Calendis ne déconnecte pas automatiquement Account.

### Erreurs retournées à un produit

Account ne redirige pas vers une URL arbitraire. Pour un échec qui doit être
affiché sur le produit, `authentication-flash-relay.ts` crée un ticket Redis
opaque, avec une URL déjà déclarée dans `authenticationFlashUri`.

Le produit consomme ce ticket dans son API flash, écrit son cookie `c_flh`, puis
redirige vers `/login`. Une visite directe de l’API flash doit rediriger vers la
page de connexion, pas afficher un JSON brut. Les codes de flash restent des
codes internes ; seule la page produit les transforme en message français.

## Passkeys

### Propriétés de sécurité

- origine et RP ID strictement vérifiés ;
- `userVerification: required` ;
- discoverable credential obligatoire pour la connexion sans email ;
- challenges Redis à usage unique et liés au navigateur ;
- aucune clé privée ne traverse le réseau ;
- clé publique, compteur et transports seulement sont stockés ;
- compteur mis à jour après authentification réussie ;
- ajout de passkey limité à une authentification récente ;
- renommage et suppression limités au propriétaire connecté.

### Limites à expliquer à l’utilisateur

Une passkey peut être synchronisée par iCloud Keychain, Google Password Manager
ou un autre gestionnaire, mais ce comportement est choisi par le navigateur et
le système d’exploitation. Chrome et Safari ne partagent pas nécessairement la
même passkey. Le message d’interface doit donc parler de disponibilité sur les
appareils et navigateurs liés au gestionnaire de passkeys, plutôt que promettre
une compatibilité universelle.

## Alertes et audit de sécurité

`SecurityEventService` ajoute des événements minimaux dans Firestore. Il ne
bloque jamais une connexion lorsque l’audit est indisponible : la disponibilité
de l’authentification reste prioritaire, et l’échec est journalisé côté serveur.

`AuthWarningService` envoie `AuthWarningEmail` après des signaux utiles, tels
qu’un verrouillage du code ou un refus mobile. L’email :

- ne contient aucun secret ;
- indique le produit, la date, le navigateur/appareil et la localisation si elle
  est un jour disponible ;
- précise qu’aucune session n’a été créée lorsque la vérification échoue ;
- propose l’accès aux réglages de sécurité Account.

La localisation est actuellement `null`. Si un fournisseur IP est ajouté, il
doit fournir une zone approximative, jamais une position GPS précise, et les
coordonnées ne sont pas nécessaires au template.

## Référence des routes HTTP

### Authentification navigateur Account

| Route | Rôle |
| --- | --- |
| `POST /api/auth/start` | Démarre une connexion directe après ID token Firebase. |
| `POST /api/auth/confirm-device` | Valide un code email et crée une session. |
| `POST /api/auth/confirm-mobile` | Termine une approbation mobile acceptée. |
| `POST /api/auth/verification/email/resend` | Renvoie un code avec protections. |
| `POST /api/auth/verification/cancel` | Annule une vérification email. |
| `POST /api/auth/verification-modes` | Retourne les méthodes disponibles. |
| `GET /api/auth/session` | Vérifie la session courante. |
| `POST /api/auth/logout` | Révoque/efface la session selon le contrat de route. |

### SSO Web et passkeys

| Route | Appelant normal | Rôle |
| --- | --- | --- |
| `POST /api/auth/web/identity` | Serveur produit | Émet un ticket d’identité après email/password ou OAuth Firebase. |
| `POST /api/auth/passkeys/web/identity` | Serveur produit | Émet un ticket d’identité sans utilisateur pour une passkey. |
| `GET /api/auth/web/authorize` | Navigateur | Consomme le ticket et initialise l’autorisation liée au navigateur. |
| `GET /api/auth/web/continue` | Navigateur | Lance ou reprend le contrôle de l’appareil. |
| `POST /api/auth/web/token` | Serveur produit | Échange le grant SSO contre la session du produit. |
| `GET /api/auth/passkeys/options` | Page Account passkey | Émet les options WebAuthn. |
| `POST /api/auth/passkeys/verify` | Page Account passkey | Vérifie l’assertion et produit un custom token Firebase. |
| `POST /api/auth/passkeys/bind` | Page Account passkey | Lie l’ID token Firebase au SSO. |

Les routes WebAuthn Account vérifient explicitement l’hôte Account. Les routes
serveur à serveur exigent le secret client ; elles ne reposent pas sur le
navigateur pour cette preuve.

### Gestion du compte

| Préfixe | Ressource |
| --- | --- |
| `/api/account/devices` | Liste, renommage et révocation des appareils. |
| `/api/account/sessions` | Liste et révocation des sessions. |
| `/api/account/passkeys` | Liste, enregistrement, renommage et suppression des passkeys. |

Toutes ces routes passent par `resolveAccountRequestSession`, qui impose l’hôte
Account et vérifie les deux cookies de session.

## Référence fichier par fichier

### `authentication/`

| Fichier | Responsabilité |
| --- | --- |
| `authentication-identity-server.ts` | Adaptateur Firebase Admin : vérifie l’ID token révoqué, résout l’utilisateur, refuse un compte désactivé et marque l’email vérifié après preuve du code. |
| `authentication-service.ts` | Orchestrateur de connexion : identité → appareil → vérification éventuelle → session. Gère aussi renvoi, annulation et finalisation mobile. |
| `authentication-server.ts` | Compose l’instance singleton avec ses dépendances serveur. |

### `audit/`

| Fichier | Responsabilité |
| --- | --- |
| `security-event-repository.ts` | Accès Firestore des événements de sécurité. |
| `security-event-service.ts` | Crée des événements expirables, sans rendre l’auth indisponible si l’audit échoue. |
| `security-event-server.ts` | Assemble le service et son repository. |

### `cookies/` et `http/`

| Fichier | Responsabilité |
| --- | --- |
| `cookies/auth-cookie.ts` | Décrit les cookies de manière indépendante de Next.js. |
| `http/auth-cookies.ts` | Écrit et efface les cookies Auth sur les réponses Next.js. |
| `http/auth-http.ts` | Validation des corps JSON, identifiants, même origine, hôte Account, résolution d’application et erreurs API sûres. |
| `http/auth-request-session.ts` | Résout une session Account complète pour les API de sécurité. |

### `device/`

| Fichier | Responsabilité |
| --- | --- |
| `device-detection.ts` | Détecte raisonnablement navigateur, OS, catégorie et appareil via Bowser. Ce n’est pas une empreinte infaillible. |
| `device-repository.ts` | Persistance Firestore et validation des documents device. |
| `device-service.ts` | Création, reconnaissance, vérification, expiration, renommage et révocation d’appareils. |
| `device-management-service.ts` | Cas d’usage Account pour gérer les appareils. |
| `device-management-server.ts` | Singleton de gestion. |
| `device-server.ts` | Singleton du service de confiance d’appareil. |

### `session/`

| Fichier | Responsabilité |
| --- | --- |
| `session-firebase.ts` | Adaptateur des session cookies Firebase Admin. |
| `session-repository.ts` | Sessions applicatives Firestore, hashes et révocations. |
| `session-service.ts` | Crée, vérifie, touche et révoque les sessions ; contrôle aussi l’appareil. |
| `session-management-service.ts` | Cas d’usage de l’espace sécurité : listes et révocations utilisateur. |
| `session-management-server.ts` | Singleton de gestion de sessions. |
| `session-server.ts` | Singleton du service de session. |

### `verification/`

| Fichier | Responsabilité |
| --- | --- |
| `verification-repository.ts` | Stockage Redis et transitions atomiques de vérification. |
| `verification-scripts.ts` | Scripts Lua : tentative de code, renvoi, annulation, approbation et consommation. |
| `verification-service.ts` | Règles métier code email/mobile, verrouillage, événements et alertes. |
| `verification-email-service.ts` | Construction et envoi du code email. |
| `verification-rate-limit-repository.ts` | État Redis des limites initiales, renvois et pénalités. |
| `verification-rate-limit-scripts.ts` | Scripts Lua de réservation et pénalité atomiques. |
| `verification-rate-limit-service.ts` | Politique de limitation progressive. |
| `auth-warning-service.ts` | Prépare et envoie `AuthWarningEmail` sans secret. |
| `auth-warning-server.ts` | Configure les marques Assosync, Calendis et Collectineo. |
| `verification-server.ts` | Assemble le service de vérification. |

### `passkey/`

| Fichier | Responsabilité |
| --- | --- |
| `passkey-http.ts` | Valide les réponses WebAuthn non fiables reçues du navigateur. |
| `passkey-challenge-repository.ts` | Challenges Redis à usage unique, liés au navigateur et à une TTL. |
| `passkey-repository.ts` | Clés publiques et métadonnées Firestore. |
| `passkey-service.ts` | Options, vérification, compteurs, enregistrement, renommage et suppression. |
| `passkey-server.ts` | Assemble le service WebAuthn. |

### `mobile/`

| Fichier | Responsabilité |
| --- | --- |
| `mobile/installation/installation-repository.ts` | Stockage des installations mobiles. |
| `mobile/installation/installation-service.ts` | Enregistre, désactive et recherche les installations actives. |
| `mobile/installation/installation-server.ts` | Singleton des installations mobiles. |
| `mobile/notification/notification-service.ts` | Envoie les notifications aux installations actives et traite les résultats. |
| `mobile/notification/notification-server.ts` | Singleton de notification FCM. |
| `mobile/approval/approval-service.ts` | Démarre, affiche et traite l’acceptation/refus mobile. |
| `mobile/approval/approval-server.ts` | Singleton d’approbation. |
| `mobile/http/mobile-request-identity.ts` | Valide l’identité Firebase et l’installation mobile appelante. |

### `web/`

| Fichier | Responsabilité |
| --- | --- |
| `authorization-repository.ts` | États Redis SSO : tickets, requests, grants et validations de lecture. |
| `authorization-scripts.ts` | Scripts Lua atomiques du SSO. |
| `authorization-service.ts` | Client confidentiel, PKCE, tickets, liaison passkey et échange de grant. |
| `authorization-server.ts` | Singleton SSO. |
| `authorization-http.ts` | Résout et contraint l’autorisation liée au navigateur. |
| `authorization-continuation-http.ts` | Lance le contrôle device et redirige vers confirmation ou callback produit. |
| `authorization-finalization.ts` | Termine le SSO, crée la session Account parallèle et nettoie en cas d’échec. |
| `authentication-flash-relay.ts` | Crée les tickets flash opaques, à usage unique et temporaires vers les produits. |

### `shared/`

| Fichier | Responsabilité |
| --- | --- |
| `auth-error.ts` | Erreur métier structurée, code public et éventuel délai de retry. |
| `auth-logger.ts` | Journalisation serveur assainie avec `requestId`. La stack n’est exposée qu’en développement dans les logs serveur. |
| `firebase-auth-error.ts` | Conversion des erreurs Firebase en erreurs Auth stables. |
| `runtime-server.ts` | Horloge système, générateurs cryptographiques et hashers partagés. |

## Diagnostic

### Première règle : conserver le `requestId`

Les réponses d’erreur API portent `X-Request-Id`. Les logs serveur utilisent la
même valeur. Pour un incident, conserver : route, statut HTTP, `requestId`,
application, étape du flux et heure. Ne jamais copier les cookies, ID tokens,
codes email, tokens Redis ou secrets client dans un ticket de support.

### Symptômes fréquents

| Symptôme | Cause probable | Vérification / action sûre |
| --- | --- | --- |
| `authorization_invalid` pendant un SSO | Transaction, cookie `webAuthorization`, ticket ou grant expiré/consommé. | Repartir depuis `/login`; contrôler les TTL Redis et l’hôte utilisé. |
| `The stored Web authorization identity is invalid.` | Ancienne donnée Redis incompatible ou liaison passkey interrompue. | En développement, attendre la TTL ou supprimer uniquement les clés temporaires Auth concernées ; ne pas modifier une donnée de production à l’aveugle. |
| `verification_expired` | Code ou vérification expiré. | Recommencer depuis le login du produit. |
| `verification_locked` | Trop de codes erronés. | Attendre la période indiquée ; l’utilisateur reçoit une alerte lors du nouveau verrouillage. |
| `verification_rate_limited` | Trop de codes email demandés. | Le produit doit consommer le flash et afficher le délai 15 min / 1 h / 6 h / 24 h. |
| Passkey annulée ou indisponible | Challenge annulé, expiré ou aucune passkey disponible dans ce gestionnaire. | Redirection produit et flash. Réessayer email/mot de passe ou enregistrer une passkey dans le navigateur concerné. |
| `session_invalid` | Cookie supprimé, token révoqué, session Firestore absente ou mauvais produit. | Les cookies sont effacés ; revenir au login du produit. |
| Boucle sur `/confirm-device` | Ancien cache de développement, paramètres absents, ou composant client qui navigue/recharge de façon répétée. | Vérifier les requêtes réseau, vider seulement le build/cache de développement puis redémarrer ; contrôler que la page ne soumet rien automatiquement. |
| JSON visible sur une API flash | L’endpoint a été ouvert comme document ou le relais produit est incomplet. | Une navigation document doit rediriger vers `/login`; une requête `fetch` doit consommer le code et effacer le cookie flash. |

### Ordre de diagnostic d’un parcours Web

1. Vérifier que le produit a bien obtenu un ID token Firebase.
2. Vérifier l’appel serveur produit vers `/api/auth/web/identity` ou
   `/api/auth/passkeys/web/identity`.
3. Vérifier le redirect vers `Account /api/auth/web/authorize`.
4. Vérifier le cookie Account `webAuthorization`.
5. Vérifier `/api/auth/web/continue` : appareil connu ou URL
   `/confirm-device`.
6. En cas de nouveau navigateur, vérifier la clé Redis de vérification puis la
   réception email ou la notification mobile.
7. Après succès, vérifier qu’un grant temporaire est créé puis consommé par le
   callback serveur du produit.
8. Vérifier les deux cookies HTTP-only du produit et sa route protégée.

## Vérifications avant mise en production

- Utiliser HTTPS partout, y compris les callbacks déclarés.
- Générer des secrets client distincts d’au moins 32 octets pour chaque produit.
- Vérifier que les variables privées ne sont jamais exposées au client.
- Déployer les règles Firestore, index requis et règles TTL correspondant aux
  champs `expires` des documents concernés.
- Restreindre l’accès Firestore direct aux données Account ; les écritures de
  sécurité doivent passer par les services serveur.
- Configurer le reverse proxy pour les en-têtes forwarded de confiance.
- Vérifier la configuration Firebase Admin, Resend, Upstash Redis et FCM.
- Tester le parcours complet : device connu, nouveau device, mauvais code,
  expiration, renvoi, verrouillage, annulation, passkey, révocation de session
  et révocation d’appareil.
- Tester Calendis et Collectineo séparément : leurs secrets, ports de
  développement et callbacks sont distincts.
- Vérifier que la page de sécurité et les emails n’affichent jamais de token,
  code de vérification ou donnée de localisation trop précise.

## Évolutions prévues

- Intégrer les formulaires OAuth Google et Microsoft dans les produits, puis
  réutiliser le chemin Firebase ID token déjà décrit.
- Construire les applications mobiles Calendis et Collectineo pour activer le
  parcours FCM et le BottomSheet d’approbation.
- Ajouter des tests d’intégration avec Redis, Firestore, Firebase et les deux
  applications Web.
- Documenter les écrans produits et leurs endpoints flash/callback à côté de
  leurs implémentations respectives.
