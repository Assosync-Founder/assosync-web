import 'server-only';

import SecurityEventService from '@/lib/auth/audit/security-event-service';
import AuthError from '@/lib/auth/shared/auth-error';
import type {
	AuthWarningNotifier,
	EmailVerificationRateLimitDecision,
	EmailVerificationRateLimitInput,
	EmailVerificationRateLimitRepository
} from '@/types/auth';

/** Enforces progressive limits on verification email requests. */
class VerificationRateLimitService {
	/**
	 * Creates an email-verification rate-limit service.
	 * @param repository - Redis rate-limit repository.
	 * @param securityEvents - Secret-free security event recorder.
	 * @param authWarnings - Best-effort suspicious-authentication notifier.
	 */
	constructor(
		private readonly repository:
		EmailVerificationRateLimitRepository,
		private readonly securityEvents: SecurityEventService,
		private readonly authWarnings: AuthWarningNotifier
	) {}

	/**
	 * Reserves an initial verification email.
	 * @param input - Account and application identity.
	 * @throws {AuthError} When email delivery is temporarily blocked.
	 */
	readonly reserveInitialEmail = async (
		input: EmailVerificationRateLimitInput
	): Promise<void> => {
		const decision =
			await this.repository.reserveInitialEmail(input);

		await this.assertAllowed(input, decision);
	};

	/**
	 * Ensures email resending is not globally blocked.
	 * @param input - Account and application identity.
	 * @throws {AuthError} When email delivery is temporarily blocked.
	 */
	readonly assertResendAllowed = async (
		input: EmailVerificationRateLimitInput
	): Promise<void> => {
		const decision = await this.repository.check(input);

		await this.assertAllowed(input, decision);
	};

	/**
	 * Applies the next progressive penalty.
	 * @param input - Account and application identity.
	 * @returns Remaining blocking time in milliseconds.
	 */
	readonly penalize = async (
		input: EmailVerificationRateLimitInput
	): Promise<number> => {
		const decision = await this.repository.penalize(input);

		if (decision.allowed) {
			throw new Error(
				'The verification penalty was not applied.'
			);
		}

		await this.recordPenalty(input, decision);

		return decision.retryAfterMs;
	};

	/**
	 * Rejects a blocked email operation.
	 * @param decision - Redis rate-limit decision.
	 * @throws {AuthError} When the decision is blocked.
	 */
	private readonly assertAllowed = async (
		input: EmailVerificationRateLimitInput,
		decision: EmailVerificationRateLimitDecision
	): Promise<void> => {
		if (decision.allowed) {
			return;
		}

		await this.recordPenalty(input, decision);

		throw new AuthError(
			'verification_rate_limited',
			'Verification email delivery is temporarily limited.',
			Math.ceil(decision.retryAfterMs / 1_000)
		);
	};

	/** Records a newly applied progressive penalty once. */
	private readonly recordPenalty = async (
		input: EmailVerificationRateLimitInput,
		decision: Exclude<
			EmailVerificationRateLimitDecision,
			{ readonly allowed: true }
		>
	): Promise<void> => {
		if (!decision.penaltyApplied) {
			return;
		}

		await this.securityEvents.record({
			userId: input.userId,
			type: 'device_verification_rate_limited',
			applicationId: input.applicationId,
			deviceId: input.deviceId,
			sessionId: null,
			affectedCount: decision.penaltyLevel
		});

		await this.authWarnings.notify({
			userId: input.userId,
			applicationId: input.applicationId,
			deviceId: input.deviceId,
			verificationId: null,
			trigger: 'verification_rate_limited',
			occurredAt: input.requestedAt,
			penaltyLevel: decision.penaltyLevel
		});
	};
}

export default VerificationRateLimitService;
