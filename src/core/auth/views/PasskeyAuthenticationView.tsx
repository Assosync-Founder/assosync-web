'use client';

import { useEffect, useRef } from 'react';
import { startAuthentication } from '@simplewebauthn/browser';
import type { PublicKeyCredentialRequestOptionsJSON } from '@simplewebauthn/browser';
import {
	inMemoryPersistence,
	setPersistence,
	signInWithCustomToken
} from 'firebase/auth';
import firebaseClient from '@/services/firebase/firebase-client';
import type { PasskeyAuthenticationViewProps } from '@/types/passkey';

const isRecord = (value: unknown): value is Record<string, unknown> => {
	return typeof value === 'object' && value !== null;
};

const isAuthenticationOptions = (
	value: unknown
): value is PublicKeyCredentialRequestOptionsJSON => {
	return isRecord(value) && typeof value.challenge === 'string';
};

/** Runs the Account-hosted passkey authentication ceremony.
 * @param authorizationId - Active browser-bound SSO authorization.
 * @param failureUri - Trusted product endpoint receiving ceremony failures.
 * @returns Transitional passkey authentication interface.
 */
const PasskeyAuthenticationView = ({
	authorizationId,
	failureUri
}: PasskeyAuthenticationViewProps) => {
	const started = useRef(false);

	useEffect(() => {
		if (started.current) {
			return;
		}

		started.current = true;

		const authenticate = async (): Promise<void> => {
			try {
				const optionsResponse = await fetch(
					`/api/auth/passkeys/options?authorization=${encodeURIComponent(authorizationId)}`,
					{ cache: 'no-store' }
				);
				const issued: unknown = await optionsResponse.json();

				if (
					!optionsResponse.ok ||
					!isRecord(issued) ||
					typeof issued.challengeId !== 'string' ||
					!isAuthenticationOptions(issued.options)
				) {
					window.location.replace(failureUri);

					return;
				}

				const assertion = await startAuthentication({
					optionsJSON: issued.options
				});
				const verificationResponse = await fetch(
					'/api/auth/passkeys/verify',
					{
						method: 'POST',
						headers: { 'Content-Type': 'application/json' },
						body: JSON.stringify({
							authorizationId,
							challengeId: issued.challengeId,
							response: assertion
						})
					}
				);
				const verification: unknown = await verificationResponse.json();

				if (
					!verificationResponse.ok ||
					!isRecord(verification) ||
					typeof verification.customToken !== 'string'
				) {
					window.location.replace(failureUri);

					return;
				}

				await setPersistence(firebaseClient.auth, inMemoryPersistence);

				const credential = await signInWithCustomToken(
					firebaseClient.auth,
					verification.customToken
				);
				const idToken = await credential.user.getIdToken(true);
				const bindResponse = await fetch('/api/auth/passkeys/bind', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ authorizationId, idToken })
				});
				const binding: unknown = await bindResponse.json();

				if (
					!bindResponse.ok ||
					!isRecord(binding) ||
					typeof binding.continuationUrl !== 'string'
				) {
					window.location.replace(failureUri);

					return;
				}

				window.location.replace(binding.continuationUrl);
			} catch {
				window.location.replace(failureUri);
			}
		};

		void authenticate();
	}, [authorizationId, failureUri]);

	return (
		<main className="mx-auto flex min-h-dvh max-w-lg items-center justify-center p-6">
			<div>
				<h1>Connexion avec une passkey</h1>
				<p>Confirmez votre identité avec Touch ID ou Windows Hello.</p>
			</div>
		</main>
	);
};

export default PasskeyAuthenticationView;
