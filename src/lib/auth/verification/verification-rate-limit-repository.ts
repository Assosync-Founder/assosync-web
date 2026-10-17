import type { Redis } from '@upstash/redis';
import {
	applyEmailVerificationPenaltyScript,
	checkEmailVerificationLimitScript,
	reserveInitialVerificationEmailScript
} from '@/lib/auth/verification/verification-rate-limit-scripts';
import type {
	EmailVerificationRateLimitDecision,
	EmailVerificationRateLimitOptions,
	EmailVerificationRateLimitRepository
} from '@/types/auth';

const RATE_LIMIT_PREFIX = 'auth:email-verification-rate-limit';

/** Determines whether an unknown value is a record.
 * @param value - Value to inspect.
 * @returns Whether the value is a string-keyed record.
 */
const isRecord = (
	value: unknown
): value is Record<string, unknown> => {
	return (
		typeof value === 'object' &&
		value !== null &&
		!Array.isArray(value)
	);
};

/** Normalizes a JSON value returned by Redis.
 * @param value - Serialized or automatically deserialized Redis value.
 * @returns The normalized unknown value.
 * @throws {SyntaxError} When a serialized value contains invalid JSON.
 */
const parseJson = (
	value: unknown
): unknown => {
	if (typeof value === 'string') {
		return JSON.parse(value);
	}

	return value;
};

/** Validates a public rate-limit decision returned by Redis.
 * @param value - Unknown Redis script result.
 * @returns The validated rate-limit decision.
 * @throws {TypeError} When the result is malformed.
 */
const parseDecision = (
	value: unknown
): EmailVerificationRateLimitDecision => {
	const parsed = parseJson(value);

	if (!isRecord(parsed)) {
		throw new TypeError(
			'The email verification rate-limit result is invalid.'
		);
	}

	if (parsed.allowed === true) {
		return { allowed: true };
	}

	if (
		parsed.allowed === false &&
		typeof parsed.retryAfterMs === 'number' &&
		Number.isFinite(parsed.retryAfterMs) &&
		parsed.retryAfterMs > 0 &&
		typeof parsed.penaltyLevel === 'number' &&
		Number.isSafeInteger(parsed.penaltyLevel) &&
		parsed.penaltyLevel >= 1 &&
		parsed.penaltyLevel <= 4 &&
		typeof parsed.penaltyApplied === 'boolean'
	) {
		return {
			allowed: false,
			retryAfterMs: parsed.retryAfterMs,
			penaltyLevel: parsed.penaltyLevel,
			penaltyApplied: parsed.penaltyApplied
		};
	}

	throw new TypeError(
		'The email verification rate-limit result is invalid.'
	);
};

/** Builds the account and application penalty key.
 * @param userId - Firebase user identifier.
 * @param applicationId - Application identifier.
 * @returns The Redis penalty key.
 */
const getPenaltyKey = (
	userId: string,
	applicationId: string
): string => {
	return [
		RATE_LIMIT_PREFIX,
		encodeURIComponent(userId),
		encodeURIComponent(applicationId),
		'penalty'
	].join(':');
};

/** Builds the initial-email fixed-window key.
 * @param userId - Firebase user identifier.
 * @param applicationId - Application identifier.
 * @returns The Redis fixed-window key.
 */
const getInitialEmailWindowKey = (
	userId: string,
	applicationId: string
): string => {
	return [
		RATE_LIMIT_PREFIX,
		encodeURIComponent(userId),
		encodeURIComponent(applicationId),
		'initial-window'
	].join(':');
};

/** Creates the Redis email-verification rate-limit repository.
 * @param redis - Shared Redis client.
 * @param options - Progressive rate-limit settings.
 * @returns The email-verification rate-limit repository.
 * @throws {RangeError} When the settings are invalid.
 */
const createEmailVerificationRateLimitRepository = (
	redis: Redis,
	options: EmailVerificationRateLimitOptions
): EmailVerificationRateLimitRepository => {
	if (
		!Number.isSafeInteger(options.initialEmailWindowMs) ||
		options.initialEmailWindowMs <= 0 ||
		!Number.isSafeInteger(options.maxInitialEmailsPerWindow) ||
		options.maxInitialEmailsPerWindow <= 0 ||
		!Number.isSafeInteger(options.penaltyResetMs) ||
		options.penaltyResetMs <= 0 ||
		options.penaltyDurationsMs.some((duration) => {
			return !Number.isSafeInteger(duration) || duration <= 0;
		})
	) {
		throw new RangeError(
			'The email verification rate-limit configuration is invalid.'
		);
	}

	const penalize: EmailVerificationRateLimitRepository['penalize'] =
		async (input) => {
			const result = await redis.eval<string[], unknown>(
				applyEmailVerificationPenaltyScript,
				[
					getPenaltyKey(
						input.userId,
						input.applicationId
					)
				],
				[
					input.requestedAt.getTime().toString(),
					options.penaltyResetMs.toString(),
					...options.penaltyDurationsMs.map((duration) => {
						return duration.toString();
					})
				]
			);

			return parseDecision(result);
		};

	return {
		check: async (input) => {
			const result = await redis.eval<string[], unknown>(
				checkEmailVerificationLimitScript,
				[
					getPenaltyKey(
						input.userId,
						input.applicationId
					)
				],
				[input.requestedAt.getTime().toString()]
			);

			return parseDecision(result);
		},

		reserveInitialEmail: async (input) => {
			const result = await redis.eval<string[], unknown>(
				reserveInitialVerificationEmailScript,
				[
					getPenaltyKey(
						input.userId,
						input.applicationId
					),
					getInitialEmailWindowKey(
						input.userId,
						input.applicationId
					)
				],
				[
					input.requestedAt.getTime().toString(),
					options.maxInitialEmailsPerWindow.toString(),
					options.initialEmailWindowMs.toString()
				]
			);
			const parsed = parseJson(result);

			if (
				isRecord(parsed) &&
				parsed.allowed === false &&
				parsed.requiresPenalty === true
			) {
				return penalize(input);
			}

			return parseDecision(parsed);
		},

		penalize
	};
};

export default createEmailVerificationRateLimitRepository;
