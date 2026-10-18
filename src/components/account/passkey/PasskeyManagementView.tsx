'use client';

import { useEffect, useState } from 'react';
import { startRegistration, type PublicKeyCredentialCreationOptionsJSON } from '@simplewebauthn/browser';
import type { AccountPasskey } from '@/types/passkey';

const isRecord = (value: unknown): value is Record<string, unknown> => {
	return typeof value === 'object' && value !== null;
};

const isRegistrationOptions = (value: unknown): value is PublicKeyCredentialCreationOptionsJSON => {
	return (
		isRecord(value) &&
		typeof value.challenge === 'string' &&
		isRecord(value.rp) &&
		isRecord(value.user) &&
		Array.isArray(value.pubKeyCredParams)
	);
};

const isAccountPasskey = (value: unknown): value is AccountPasskey => {
	if (!isRecord(value)) {
		return false;
	}

	return (
		typeof value.id === 'string' &&
		(value.displayName === null ||
			typeof value.displayName === 'string') &&
		(value.deviceType === 'singleDevice' ||
			value.deviceType === 'multiDevice') &&
		typeof value.backedUp === 'boolean' &&
		(value.lastUsedAt === null ||
			typeof value.lastUsedAt === 'string') &&
		typeof value.createdAt === 'string'
	);
};

const readPasskeys = (value: unknown): readonly AccountPasskey[] => {
	if (!isRecord(value) || !Array.isArray(value.passkeys) || !value.passkeys.every(isAccountPasskey)) {
		throw new TypeError('The passkey list response is invalid.');
	}

	return value.passkeys;
};

const formatDate = (value: string): string => {
	return new Intl.DateTimeFormat('fr-FR', { dateStyle: 'long', timeStyle: 'short' }).format(new Date(value));
};

/** Lists and registers passkeys from the Account security settings. */
const PasskeyManagementView = () => {
	const [passkeys, setPasskeys] = useState<readonly AccountPasskey[]>([]);
	const [loading, setLoading] = useState(true);
	const [pending, setPending] = useState(false);
	const [editingId, setEditingId] = useState<string | null>(null);
	const [displayName, setDisplayName] = useState('');
	const [message, setMessage] = useState<string | null>(null);

	const loadPasskeys = async (): Promise<void> => {
		const response = await fetch('/api/account/passkeys', { cache: 'no-store' });
		const result: unknown = await response.json();

		if (!response.ok) {
			throw new Error('Passkey list unavailable.');
		}

		setPasskeys(readPasskeys(result));
	};

	const rename = async (passkeyId: string): Promise<void> => {
		const normalizedDisplayName = displayName.trim();

		if (!normalizedDisplayName) {
			setMessage('Le nom de la passkey est obligatoire.');

			return;
		}

		setPending(true);
		setMessage(null);

		try {
			const response = await fetch(
				`/api/account/passkeys/${encodeURIComponent(passkeyId)}`,
				{
					method: 'PATCH',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ displayName: normalizedDisplayName })
				}
			);

			if (!response.ok) {
				setMessage('Impossible de renommer cette passkey.');

				return;
			}

			await loadPasskeys();
			setEditingId(null);
			setDisplayName('');
			setMessage('La passkey a été renommée.');
		} catch (_error: unknown) {
			setMessage('Impossible de renommer cette passkey.');
		} finally {
			setPending(false);
		}
	};

	const remove = async (passkeyId: string): Promise<void> => {
		if (!window.confirm('Supprimer définitivement cette passkey ?')) {
			return;
		}

		setPending(true);
		setMessage(null);

		try {
			const response = await fetch(`/api/account/passkeys/${encodeURIComponent(passkeyId)}`, { method: 'DELETE' });

			if (!response.ok) {
				setMessage('Impossible de supprimer cette passkey.');

				return;
			}

			await loadPasskeys();
			setEditingId(null);
			setDisplayName('');
			setMessage('La passkey a été supprimée.');
		} catch (_error: unknown) {
			setMessage('Impossible de supprimer cette passkey.');
		} finally {
			setPending(false);
		}
	};

	useEffect(() => {
		const load = async (): Promise<void> => {
			try {
				await loadPasskeys();
			} catch (_error: unknown) {
				setMessage('Impossible de charger vos passkeys.');
			} finally {
				setLoading(false);
			}
		};

		void load();
	}, []);

	const register = async (): Promise<void> => {
		setPending(true);
		setMessage(null);

		try {
			const optionsResponse = await fetch('/api/account/passkeys/registration/options', { method: 'POST' });
			const issued: unknown = await optionsResponse.json();

			if (!optionsResponse.ok || !isRecord(issued) || typeof issued.challengeId !== 'string' || !isRegistrationOptions(issued.options)) {
				setMessage('Impossible d’ajouter cette passkey.');

				return;
			}

			const credential = await startRegistration({ optionsJSON: issued.options });
			const verificationResponse = await fetch(
				'/api/account/passkeys/registration/verify',
				{
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ challengeId: issued.challengeId, response: credential })
				}
			);

			if (!verificationResponse.ok) {
				setMessage('Impossible d’ajouter cette passkey.');

				return;
			}

			await loadPasskeys();
			setMessage('La passkey a été ajoutée à votre compte.');
		} catch (caught: unknown) {
			setMessage(
				caught instanceof Error && caught.name === 'NotAllowedError'
					? 'La création de la passkey a été annulée.'
					: 'Impossible d’ajouter cette passkey.'
			);
		} finally {
			setPending(false);
		}
	};

	return (
		<section>
			<h2>Passkeys</h2>
			<p>Utilisez Touch ID ou Windows Hello pour vous connecter.</p>

			<h3>Vos passkeys</h3>
			{loading ? <p>Chargement…</p> : null}
			{!loading && passkeys.length === 0 ? (
				<p>Aucune passkey n’est encore enregistrée.</p>
			) : null}
			{passkeys.length > 0 ? (
				<ul>
					{passkeys.map((passkey) => (
						<li key={passkey.id}>
							<strong>
								{passkey.displayName ??
									(passkey.deviceType === 'multiDevice'
										? 'Passkey synchronisée'
										: 'Passkey de cet appareil')}
							</strong>
							<p>Ajoutée le {formatDate(passkey.createdAt)}</p>
							<p>
								{passkey.lastUsedAt
									? `Dernière utilisation le ${formatDate(passkey.lastUsedAt)}`
									: 'Jamais utilisée'}
							</p>
							{passkey.backedUp ? (
								<p>Synchronisée par votre gestionnaire de passkeys</p>
							) : null}
							{editingId === passkey.id ? (
								<form
									onSubmit={(event) => {
										event.preventDefault();
										void rename(passkey.id);
									}}
								>
									<label htmlFor={`passkey-name-${passkey.id}`}>
										Nom de la passkey
									</label>
									<input
										id={`passkey-name-${passkey.id}`}
										value={displayName}
										maxLength={80}
										required
										disabled={pending}
										onChange={(event) => {
											setDisplayName(event.target.value);
										}}
									/>
									<button type="submit" disabled={pending}>
										Enregistrer
									</button>
									<button
										type="button"
										disabled={pending}
										onClick={() => {
											setEditingId(null);
											setDisplayName('');
										}}
									>
										Annuler
									</button>
								</form>
							) : (
								<button
									type="button"
									disabled={pending}
									onClick={() => {
										setEditingId(passkey.id);
										setDisplayName(passkey.displayName ?? '');
									}}
								>
									Renommer
								</button>
							)}
							<button
								type="button"
								disabled={pending}
								onClick={() => {
									void remove(passkey.id);
								}}
							>
								Supprimer
							</button>
						</li>
					))}
				</ul>
			) : null}

			<button
				type="button"
				disabled={pending}
				onClick={() => {
					void register();
				}}
			>
				{pending ? 'Configuration…' : 'Ajouter une passkey'}
			</button>
			{message ? <p role="status">{message}</p> : null}
		</section>
	);
};

export default PasskeyManagementView;
