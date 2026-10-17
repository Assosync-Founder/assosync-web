import 'server-only';

import { logAuthServerError } from '@/lib/auth/shared/auth-logger';
import { systemClock } from '@/lib/auth/shared/runtime-server';
import type {
	Clock,
	CreateSecurityEventInput,
	RecordSecurityEventInput,
	SecurityEventRepository,
	SecurityEventServiceOptions
} from '@/types/auth';

/** Records minimal security events without affecting authentication availability. */
class SecurityEventService {
	/**
	 * Creates a security event service.
	 * @param repository - Append-only persistence adapter.
	 * @param options - Retention settings.
	 * @param clock - Time provider.
	 * @throws {RangeError} When the retention duration is invalid.
	 */
	constructor(
		private readonly repository: SecurityEventRepository,
		private readonly options: SecurityEventServiceOptions,
		private readonly clock: Clock = systemClock
	) {
		if (
			!Number.isSafeInteger(options.retentionMs) ||
			options.retentionMs <= 0
		) {
			throw new RangeError(
				'Security event retention must be a positive integer.'
			);
		}
	}

	/**
	 * Records an event while keeping audit-storage failures non-blocking.
	 * @param input - Secret-free event data.
	 * @returns A promise resolved after the write attempt.
	 */
	readonly record = async (
		input: RecordSecurityEventInput
	): Promise<void> => {
		const occurredAt = this.clock.now();
		const event: CreateSecurityEventInput = {
			...input,
			occurredAt,
			expiresAt: new Date(
				occurredAt.getTime() + this.options.retentionMs
			)
		};

		try {
			await this.repository.create(event);
		} catch (error: unknown) {
			logAuthServerError(
				error,
				'security_event_write'
			);
		}
	};
}

export default SecurityEventService;
