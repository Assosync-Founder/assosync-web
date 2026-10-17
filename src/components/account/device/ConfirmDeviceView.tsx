'use client';

import {
	type FormEvent,
	useEffect,
	useState
} from 'react';
import type {
	ConfirmDeviceViewProps
} from '@/types/auth';

const VERIFICATION_CODE_PATTERN = /^\d{6}$/u;

/** Reads a safe authentication error code from an API response. */
const readErrorCode = (
	value: unknown
): string | null => {
	if (
		typeof value !== 'object' ||
		value === null ||
		!('error' in value) ||
		typeof value.error !== 'string'
	) {
		return null;
	}

	return value.error;
};

/** Reads a positive retry delay from an API response. */
const readRetryAfterSeconds = (
	value: unknown
): number | null => {
	if (
		typeof value !== 'object' ||
		value === null ||
		!('retryAfterSeconds' in value) ||
		typeof value.retryAfterSeconds !== 'number' ||
		!Number.isSafeInteger(value.retryAfterSeconds) ||
		value.retryAfterSeconds <= 0
	) {
		return null;
	}

	return value.retryAfterSeconds;
};

/** Determines whether authentication must restart from the product. */
const isTerminalErrorCode = (
	errorCode: string | null
): boolean => {
	return (
		errorCode === 'verification_expired' ||
		errorCode === 'verification_locked' ||
		errorCode === 'authorization_invalid' ||
		errorCode === 'identity_invalid' ||
		errorCode === 'device_invalid'
	);
};

/**
 * Displays and submits the email device verification form.
 * @param props - Browser-bound authentication identifiers.
 * @returns The device confirmation form.
 */
const ConfirmDeviceView = ({
	authorizationId,
	deviceId,
	verificationId,
	restartUri
}: ConfirmDeviceViewProps) => {
	const [code, setCode] = useState('');
	const [error, setError] = useState<string | null>(
		null
	);
	const [isSubmitting, setIsSubmitting] =
		useState(false);
	const [isRedirecting, setIsRedirecting] =
		useState(false);
	const [isResending, setIsResending] = useState(false);
	const [isCancelling, setIsCancelling] = useState(false);
	const [isTerminal, setIsTerminal] = useState(false);
	const [resendLimitReached, setResendLimitReached] =
		useState(false);
	const [retryAfterSeconds, setRetryAfterSeconds] =
		useState(0);

	useEffect(() => {
		if (retryAfterSeconds <= 0) {
			return;
		}

		const timeout = window.setTimeout(() => {
			setRetryAfterSeconds((current) => {
				return Math.max(0, current - 1);
			});
		}, 1_000);

		return () => {
			window.clearTimeout(timeout);
		};
	}, [retryAfterSeconds]);

	let submitLabel = 'Confirmer cet appareil';

	if (isRedirecting) {
		submitLabel = 'Redirection…';
	} else if (isSubmitting) {
		submitLabel = 'Vérification…';
	}

	const handleSubmit = async (
		event: FormEvent<HTMLFormElement>
	): Promise<void> => {
		event.preventDefault();

		if (
			isSubmitting ||
			isRedirecting ||
			!VERIFICATION_CODE_PATTERN.test(code)
		) {
			setError(
				'Saisissez le code à six chiffres reçu par email.'
			);

			return;
		}

		setIsSubmitting(true);
		setError(null);

		try {
			const response = await fetch(
				'/api/auth/confirm-device',
				{
					method: 'POST',
					headers: {
						'Content-Type': 'application/json'
					},
					credentials: 'same-origin',
					body: JSON.stringify({
						authorizationId,
						deviceId,
						verificationId,
						code
					})
				}
			);

			const result: unknown = await response.json();

			if (!response.ok) {
				const errorCode = readErrorCode(result);

				if (isTerminalErrorCode(errorCode)) {
					setIsTerminal(true);
					setError(
						'Cette vérification n’est plus valide. Recommencez la connexion depuis votre application.'
					);
				} else {
					setError(
						'Le code saisi est incorrect ou ne correspond plus à cette connexion.'
					);
				}

				setIsSubmitting(false);

				return;
			}

			if (
				typeof result !== 'object' ||
				result === null ||
				!('status' in result) ||
				result.status !== 'authorization_ready' ||
				!('redirectUri' in result) ||
				typeof result.redirectUri !== 'string'
			) {
				setError(
					'Le code est incorrect, expiré ou ne correspond plus à cette connexion.'
				);
				setIsSubmitting(false);

				return;
			}

			setIsRedirecting(true);

			window.location.replace(result.redirectUri);
		} catch (error: unknown) {
			console.error(
				'Device confirmation request failed.',
				error
			);

			setError(
				'La confirmation est momentanément indisponible. Réessayez.'
			);

			setIsSubmitting(false);
		}
	};

	const handleResend = async (): Promise<void> => {
		if (
			isResending ||
			isSubmitting ||
			isRedirecting ||
			isTerminal ||
			resendLimitReached ||
			retryAfterSeconds > 0
		) {
			return;
		}

		setIsResending(true);
		setError(null);

		try {
			const response = await fetch(
				'/api/auth/verification/email/resend',
				{
					method: 'POST',
					headers: {
						'Content-Type': 'application/json'
					},
					credentials: 'same-origin',
					body: JSON.stringify({
						authorizationId,
						deviceId,
						verificationId
					})
				}
			);
			const result: unknown = await response.json();

			if (!response.ok) {
				const errorCode = readErrorCode(result);
				const retryAfter = readRetryAfterSeconds(result);

				if (retryAfter !== null) {
					setRetryAfterSeconds(retryAfter);
				}

				if (isTerminalErrorCode(errorCode)) {
					setIsTerminal(true);
					setError(
						'Cette vérification n’est plus valide. Recommencez la connexion depuis votre application.'
					);
				} else if (
					errorCode === 'verification_rate_limited'
				) {
					setError(
						'Trop de demandes ont été effectuées. L’envoi de nouveaux codes est temporairement suspendu.'
					);
				} else {
					setError(
						'Un nouveau code ne peut pas encore être demandé.'
					);
				}

				return;
			}

			if (
				typeof result !== 'object' ||
				result === null ||
				!('status' in result) ||
				result.status !== 'resent' ||
				!('resendCount' in result) ||
				typeof result.resendCount !== 'number' ||
				!('resendLimitReached' in result) ||
				typeof result.resendLimitReached !== 'boolean' ||
				!('retryAfterSeconds' in result) ||
				typeof result.retryAfterSeconds !== 'number' ||
				!Number.isSafeInteger(result.retryAfterSeconds) ||
				result.retryAfterSeconds <= 0
			) {
				console.error(
					'Email resend response is invalid.'
				);

				setError(
					'L’envoi d’un nouveau code est momentanément indisponible.'
				);

				return;
			}

			setCode('');

			if (result.resendLimitReached) {
				setResendLimitReached(true);
				setError(
					'Un dernier code vient d’être envoyé. Aucun nouvel email ne peut être demandé pour le moment.'
				);
			} else {
				setRetryAfterSeconds(result.retryAfterSeconds);
				setError('Un nouveau code vient d’être envoyé.');
			}
		} catch (error: unknown) {
			console.error(
				'Device verification resend failed.',
				error
			);

			setError(
				'L’envoi d’un nouveau code est momentanément indisponible.'
			);
		} finally {
			setIsResending(false);
		}
	};

	const handleCancel = async (): Promise<void> => {
		if (isCancelling || isRedirecting) {
			return;
		}

		setIsCancelling(true);

		try {
			await fetch('/api/auth/verification/cancel', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json'
				},
				credentials: 'same-origin',
				body: JSON.stringify({
					authorizationId,
					deviceId,
					verificationId
				})
			});
		} finally {
			window.location.replace(restartUri);
		}
	};

	return (
		<main className="flex flex-col">
			<h1>Confirmer ce nouvel appareil</h1>

			{isRedirecting ? (
				<p role="status">
					Appareil confirmé. Redirection vers votre application…
				</p>
			) : (
				<p>
					Un code à six chiffres a été envoyé à
					votre adresse email.
				</p>
			)}

			{error ? (
				<p role="alert">
					{error}
				</p>
			) : null}

			{isTerminal ? (
				<a href={restartUri}>
					Recommencer la connexion
				</a>
			) : (
				<form onSubmit={handleSubmit} className="flex flex-col">
				<label htmlFor="verification-code">
					Code de vérification
				</label>

				<input
					id="verification-code"
					name="code"
					type="text"
					inputMode="numeric"
					autoComplete="one-time-code"
					pattern="[0-9]{6}"
					value={code}
					onChange={(event) => {
						setCode(
							event.currentTarget.value
								.replace(/\D/gu, '')
								.slice(0, 6)
						);
					}}
					disabled={isSubmitting || isRedirecting}
					required
					autoFocus
				/>

				<button
					type="submit"
					disabled={
						isSubmitting ||
						isRedirecting ||
						!VERIFICATION_CODE_PATTERN.test(code)
					}
				>
					{submitLabel}
				</button>

				<button
					type="button"
					onClick={handleResend}
					disabled={
						isResending ||
						isSubmitting ||
						isRedirecting ||
						resendLimitReached ||
						retryAfterSeconds > 0
					}
				>
					{retryAfterSeconds > 0
						? `Renvoyer dans ${retryAfterSeconds} s`
						: 'Renvoyer un code'}
				</button>

				<button
					type="button"
					onClick={handleCancel}
					disabled={isCancelling || isRedirecting}
				>
					{isCancelling
						? 'Annulation…'
						: 'Annuler la connexion'}
				</button>
				</form>
			)}
		</main>
	);
};

export default ConfirmDeviceView;
