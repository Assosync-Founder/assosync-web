import 'server-only';

import { AuthWarningEmail, MailError } from '@assosync/email';
import { createElement } from 'react';
import DeviceService from '@/lib/auth/device/device-service';
import { logAuthServerError } from '@/lib/auth/shared/auth-logger';
import type {
	AuthWarningEmailServiceOptions,
	AuthWarningIdentityProvider,
	AuthWarningNotifier,
	Device,
	SendAuthWarningInput,
	VerificationEmailBrand,
	VerificationEmailSender
} from '@/types/auth';

const occurrenceFormatter = new Intl.DateTimeFormat(
	'fr-FR',
	{
		dateStyle: 'full',
		timeStyle: 'short',
		timeZone: 'Europe/Paris'
	}
);

/**
 * Returns a concise device label without browser fingerprinting.
 * @param device - Persisted browser device information.
 * @returns A human-readable device label or null.
 */
const createDeviceName = (device: Device): string | null => {
	if (device.deviceModel) {
		return device.deviceModel;
	}

	if (device.deviceBrand) {
		return device.deviceBrand;
	}

	switch (device.category) {
		case 'desktop':
			return 'Ordinateur';

		case 'mobile':
			return 'Téléphone';

		case 'tablet':
			return 'Tablette';

		case 'unknown':
			return null;
	}
};

/**
 * Returns a readable browser and operating-system description.
 * @param device - Persisted browser device information.
 * @returns A human-readable browser description or null.
 */
const createBrowserName = (device: Device): string | null => {
	if (device.browserName && device.operatingSystemName) {
		return [
			device.browserName,
			'sur',
			device.operatingSystemName
		].join(' ');
	}

	return device.browserName ?? device.operatingSystemName;
};

/** Composes and delivers deduplicated authentication warning emails. */
class AuthWarningService implements AuthWarningNotifier {
	/** Application-specific email configurations. */
	private readonly brands: ReadonlyMap<
		string,
		VerificationEmailBrand
	>;

	/**
	 * Creates an authentication warning service.
	 * @param emails - Generic transactional email sender.
	 * @param identities - Firebase account identity resolver.
	 * @param devices - Persistent browser device service.
	 * @param options - Security warning email configuration.
	 * @throws {MailError} When the configuration is invalid.
	 */
	constructor(private readonly emails: VerificationEmailSender, private readonly identities: AuthWarningIdentityProvider, private readonly devices: DeviceService, private readonly options: AuthWarningEmailServiceOptions) {
		this.brands = new Map(
			options.brands.map((brand) => {
				return [
					brand.applicationId,
					brand
				];
			})
		);

		if (this.brands.size === 0 || this.brands.size !== options.brands.length) {
			throw new MailError('config_invalid', 'Authentication warning email brands must be non-empty and unique.');
		}

		const securityUrl = new URL(options.securityUrl);

		if (securityUrl.protocol !== 'https:' && securityUrl.hostname !== 'account.localhost') {
			throw new MailError('config_invalid', 'The authentication warning security URL must be trusted.');
		}
	}

	/**
	 * Sends a warning once for a newly detected security signal.
	 * Delivery failures are logged without replacing the authentication result.
	 * @param input - Safe authentication warning context.
	 * @returns A promise resolved after the delivery attempt.
	 */
	readonly notify = async (input: SendAuthWarningInput): Promise<void> => {
		try {
			await this.send(input);
		} catch (error: unknown) {
			logAuthServerError(error, 'auth_warning_email_delivery');
		}
	};

	/**
	 * Sends one provider-level authentication warning email.
	 * @param input - Safe authentication warning context.
	 * @returns A promise resolved after provider acceptance.
	 */
	private readonly send = async (input: SendAuthWarningInput): Promise<void> => {
		const brand = this.brands.get(input.applicationId);

		if (!brand) {
			throw new MailError('input_invalid', 'The authentication warning application is invalid.');
		}

		const [identity, device] = await Promise.all([
			this.identities.resolve(input.userId),
			this.devices.findById(input.userId, input.deviceId)
		]);

		const email = createElement(
			AuthWarningEmail,
			{
				...(identity.firstname
					? {
						firstname: identity.firstname
					}
					: {}),
				type: brand.emailType,
				securityUrl: this.options.securityUrl,
				details: {
					applicationName: brand.displayName,
					occurredAt: occurrenceFormatter.format(input.occurredAt),
					deviceName: createDeviceName(device),
					browserName: createBrowserName(device),
					location: null
				}
			}
		);

		const eventIdentifier = input.verificationId ?? [
			input.deviceId,
			input.penaltyLevel?.toString() ?? '0',
			input.occurredAt.getTime().toString()
		].join('-');

		await this.emails.send({
			from: brand.from,
			to: [identity.email],
			subject: `Activité de connexion inhabituelle sur ${brand.displayName}`,
			react: email,
			...(brand.replyTo
				? {
					replyTo: brand.replyTo
				}
				: {}),
			idempotencyKey: [
				'authentication-warning',
				input.userId,
				input.applicationId,
				input.trigger,
				eventIdentifier
			].join('/'),
			tags: {
				application: brand.applicationId,
				category: 'authentication-warning',
				trigger: input.trigger
			}
		});
	};
}

export default AuthWarningService;
