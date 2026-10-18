import type { Rest } from '@assosync/firestore';
import type { Mailer, SentMail } from '@assosync/email';
import type { FirebaseCloudMessagingBatchResult, FirebaseCloudMessagingNotification } from '@/types/firebase';

/** Error codes exposed by the authentication domain. */
export type AuthErrorCode =
	| 'account_disabled'
	| 'firebase_unavailable'
	| 'identity_invalid'
	| 'approval_expired'
	| 'approval_invalid'
	| 'approval_not_ready'
	| 'approval_rejected'
	| 'authorization_invalid'
	| 'client_invalid'
	| 'device_invalid'
	| 'device_not_verified'
	| 'device_user_mismatch'
	| 'session_expired'
	| 'session_invalid'
	| 'session_revoked'
	| 'verification_expired'
	| 'verification_invalid'
	| 'verification_locked'
	| 'verification_mode_unavailable'
	| 'verification_not_ready'
	| 'verification_resend_limit'
	| 'verification_resend_too_soon'
	| 'verification_rate_limited'
	| 'webauthn_challenge_invalid'
	| 'webauthn_credential_invalid';

/** Firebase operation being normalized into an authentication error. */
export type FirebaseAuthErrorContext =
	| 'identity'
	| 'session'
	| 'session_creation'
	| 'user';

/** Provides the current time. */
export type Clock = {
	/**
	 * Returns the current date.
	 * @returns The current date.
	 */
	now: () => Date;
};

/** Generates opaque random values. */
export type TokenGenerator = {
	/**
	 * Generates a new opaque value.
	 * @returns A cryptographically secure random value.
	 */
	generate: () => string;
};

/** Hashes opaque secrets before persistence. */
export type TokenHasher = {
	/**
	 * Hashes an opaque value.
	 * @param value - Secret value to hash.
	 * @returns The encoded digest.
	 */
	hash: (value: string) => string;
};

/** Generates short human-readable verification codes. */
export type VerificationCodeGenerator = {
	/**
	 * Generates a new verification code.
	 * @returns A cryptographically secure verification code.
	 */
	generate: () => string;
};

/** Hashes short verification codes with a server-side secret. */
export type VerificationCodeHasher = {
	/**
	 * Hashes a verification code within a unique verification context.
	 * @param code - Short code entered by the user.
	 * @param verificationId - Unique verification identifier.
	 * @returns The encoded keyed digest.
	 */
	hash: (code: string, verificationId: string) => string;
};

/** Supported SameSite policies for authentication cookies. */
export type AuthCookieSameSite = 'lax' | 'strict' | 'none';

/** Describes a framework-neutral authentication cookie. */
export type AuthCookie = {
	/** Cookie name. */
	name: string;

	/** Cookie value. */
	value: string;

	/** Prevents access from browser scripts. */
	httpOnly: boolean;

	/** Restricts transport to secure browser contexts. */
	secure: boolean;

	/** Defines cross-site delivery rules. */
	sameSite: AuthCookieSameSite;

	/** Restricts the request path. */
	path: string;

	/** Defines the lifetime in seconds. */
	maxAge: number;
};

/** Describes the server-side trust state of a browser device. */
export type DeviceStatus = 'pending' | 'verified' | 'revoked';

/** Coarse device category derived from request headers. */
export type DeviceCategory =
	| 'desktop'
	| 'mobile'
	| 'tablet'
	| 'unknown';

/** Non-sensitive device information reasonably derived from HTTP headers. */
export type DetectedDeviceInformation = {
	/** Coarse category without hardware fingerprinting. */
	readonly category: DeviceCategory;

	/** Browser family when it can be identified. */
	readonly browserName: string | null;

	/** Browser major or reported version when available. */
	readonly browserVersion: string | null;

	/** Operating system family when it can be identified. */
	readonly operatingSystemName: string | null;

	/** Operating system version when explicitly reported. */
	readonly operatingSystemVersion: string | null;

	/** Device brand when reasonably known from platform information. */
	readonly deviceBrand: string | null;

	/** Device model explicitly reported through Client Hints. */
	readonly deviceModel: string | null;
};

/** Represents a browser device recognized across the Assosync account. */
export type Device = {
	/** Internal opaque device identifier. */
	readonly id: string;

	/** Hash of the secret stored in the browser cookie. */
	readonly tokenHash: string;

	/** Firebase user owning the device. */
	readonly userId: string;

	/** Application through which the device was first registered. */
	readonly applicationId: string;

	/** Optional user-facing device label. */
	readonly displayName: string | null;

	/** Coarse device category derived at first authentication. */
	readonly category: DeviceCategory;

	/** Detected browser family. */
	readonly browserName: string | null;

	/** Detected browser version. */
	readonly browserVersion: string | null;

	/** Detected operating system family. */
	readonly operatingSystemName: string | null;

	/** Detected operating system version. */
	readonly operatingSystemVersion: string | null;

	/** Reasonably detected device brand. */
	readonly deviceBrand: string | null;

	/** Device model reported through Client Hints. */
	readonly deviceModel: string | null;

	/** Current server-side trust state. */
	readonly status: DeviceStatus;

	/** Device creation time. */
	readonly createdAt: Date;

	/** Absolute time after which the device can no longer authenticate. */
	readonly expiresAt: Date;

	/** Last successful device use time. */
	readonly lastSeenAt: Date;

	/** First successful verification time. */
	readonly verifiedAt: Date | null;

	/** Device revocation time. */
	readonly revokedAt: Date | null;
};

/** Trusted-device security settings. */
export type DeviceServiceOptions = {
	/** Maximum lifetime of an unverified device in milliseconds. */
	readonly pendingLifetimeMs: number;

	/** Lifetime granted after successful device verification. */
	readonly trustedLifetimeMs: number;
};

/** Firestore representation of a recognized browser device. */
export type StoredDevice = Rest & Omit<
	Device,
	| 'id'
	| 'createdAt'
	| 'expiresAt'
	| 'lastSeenAt'
	| 'verifiedAt'
	| 'revokedAt'
> & {
	/** Absolute time after which the device can no longer authenticate. */
	readonly expires: Date;

	/** Last successful device use time. */
	readonly lastSeen: Date;

	/** First successful verification time. */
	readonly verified: Date | null;

	/** Device revocation time. */
	readonly revoked: Date | null;
};

/** Device fields required before Firestore assigns the document identifier. */
export type CreateDeviceInput = Omit<Device, 'id'>;

/** Persists recognized browser devices. */
export type DeviceRepository = {
	/**
	 * Creates a device.
	 * @param device - Device to persist.
	 * @returns The persisted device.
	 */
	readonly create: (device: CreateDeviceInput) => Promise<Device>;

	/**
	 * Finds an account device from its hashed cookie token.
	 * @param userId - Firebase user owning the device collection.
	 * @param tokenHash - Hash of the device cookie token.
	 * @returns The matching device or null.
	 */
	readonly findByTokenHash: (userId: string, tokenHash: string) => Promise<Device | null>;

	/**
	 * Finds a device from its internal identifier.
	 * @param userId - Firebase user owning the device collection.
	 * @param deviceId - Internal device identifier.
	 * @returns The matching device or null.
	 */
	readonly findById: (userId: string, deviceId: string) => Promise<Device | null>;

	/**
	 * Lists every device owned by an account.
	 * @param userId - Firebase user owning the device collection.
	 * @returns The account devices.
	 */
	readonly listByUser: (userId: string) => Promise<readonly Device[]>;

	/**
	 * Updates a complete device record.
	 * @param device - Device state to persist.
	 * @returns The updated device.
	 */
	readonly update: (device: Device) => Promise<Device>;

	/**
	 * Atomically verifies a pending device or returns its verified state.
	 * @param userId - Expected Firebase user identifier.
	 * @param deviceId - Pending device identifier.
	 * @param applicationId - Expected application identifier.
	 * @param verifiedAt - Verification time.
	 * @param expiresAt - Trusted-device expiration time.
	 * @returns The verified device or null when the transition is invalid.
	 */
	readonly verifyPending: (userId: string, deviceId: string, applicationId: string, verifiedAt: Date, expiresAt: Date) => Promise<Device | null>;

	/**
	 * Atomically updates the last-seen time of a verified device.
	 * @param userId - Expected Firebase user identifier.
	 * @param deviceId - Verified device identifier.
	 * @param seenAt - Successful use time.
	 * @returns The updated device or null when it is no longer trusted.
	 */
	readonly touchVerified: (userId: string, deviceId: string, seenAt: Date) => Promise<Device | null>;

	/**
	 * Atomically renames an active device.
	 * @param userId - Firebase user owning the device.
	 * @param deviceId - Device identifier.
	 * @param displayName - Normalized user-facing label.
	 * @returns The renamed device or null when it cannot be changed.
	 */
	readonly rename: (userId: string, deviceId: string, displayName: string | null) => Promise<Device | null>;

	/**
	 * Atomically revokes a device.
	 * @param userId - Firebase user owning the device.
	 * @param deviceId - Device identifier.
	 * @param revokedAt - Revocation time.
	 * @returns The revoked device or null when it does not exist.
	 */
	readonly revoke: (userId: string, deviceId: string, revokedAt: Date) => Promise<Device | null>;
};

/** Public account representation of a browser device. */
export type AccountDevice = Omit<Device, 'tokenHash'> & {
	/** Whether this device owns the session making the request. */
	readonly isCurrent: boolean;
};

/** Result returned after revoking a managed device. */
export type RevokeManagedDeviceResult = {
	/** Revoked device without its secret hash. */
	readonly device: AccountDevice;

	/** Number of application sessions revoked for the device. */
	readonly revokedSessionCount: number;
};

/** Security-relevant event recorded without authentication secrets. */
export type SecurityEventType =
	| 'device_verified'
	| 'device_revoked'
	| 'session_created'
	| 'session_revoked'
	| 'sessions_revoked'
	| 'mobile_approval_approved'
	| 'mobile_approval_rejected'
	| 'device_verification_expired'
	| 'device_verification_locked'
	| 'device_verification_rate_limited'
	| 'device_verification_cancelled';

/** Represents one append-only account security event. */
export type SecurityEvent = {
	/** Internal opaque event identifier. */
	readonly id: string;

	/** Firebase user owning the event. */
	readonly userId: string;

	/** Stable event category. */
	readonly type: SecurityEventType;

	/** Application related to the event when available. */
	readonly applicationId: string | null;

	/** Browser device related to the event when available. */
	readonly deviceId: string | null;

	/** Application session related to the event when available. */
	readonly sessionId: string | null;

	/** Number of affected resources for grouped events. */
	readonly affectedCount: number | null;

	/** Time at which the event occurred. */
	readonly occurredAt: Date;

	/** Time after which Firestore may delete the audit event. */
	readonly expiresAt: Date;
};

/** Firestore representation of an account security event. */
export type StoredSecurityEvent = Rest & Omit<
	SecurityEvent,
	'id' | 'occurredAt' | 'expiresAt'
> & {
	/** Time at which the event occurred. */
	readonly occurred: Date;

	/** Time after which Firestore may delete the audit event. */
	readonly expires: Date;
};

/** Security-event fields required before Firestore assigns the document identifier. */
export type CreateSecurityEventInput = Omit<SecurityEvent, 'id'>;

/** Safe input accepted by the security audit recorder. */
export type RecordSecurityEventInput = Omit<
	SecurityEvent,
	'id' | 'occurredAt' | 'expiresAt'
>;

/** Persists append-only account security events. */
export type SecurityEventRepository = {
	/**
	 * Creates a security event.
	 * @param event - Complete event to persist.
	 * @returns A promise resolved after persistence.
	 */
	readonly create: (event: CreateSecurityEventInput) => Promise<void>;
};

/** Security-event retention settings. */
export type SecurityEventServiceOptions = {
	/** Event retention duration in milliseconds. */
	readonly retentionMs: number;
};

/** Mobile applications allowed to approve authentication requests. */
export type MobileApplicationId = 'calendis' | 'collectineo';

/** Mobile platforms supported by the authentication domain. */
export type MobilePlatform = 'android' | 'ios';

/** Lifecycle state of a registered mobile application installation. */
export type MobileInstallationStatus = 'active' | 'disabled';

/** Represents an installed mobile application able to receive authentication requests. */
export type MobileInstallation = {
	/** Stable identifier generated by the mobile application installation. */
	readonly id: string;

	/** Firebase user owning the mobile installation. */
	readonly userId: string;

	/** Installed Assosync mobile application. */
	readonly mobileApplicationId: MobileApplicationId;

	/** Operating system running the mobile application. */
	readonly platform: MobilePlatform;

	/** Optional user-facing mobile device name. */
	readonly mobileDeviceName: string | null;

	/** Optional installed mobile application version. */
	readonly mobileApplicationVersion: string | null;

	/** Current Firebase Cloud Messaging registration token. */
	readonly pushToken: string;

	/** Hash used to compare push tokens without exposing them. */
	readonly pushTokenHash: string;

	/** Current registration state. */
	readonly status: MobileInstallationStatus;

	/** First registration time. */
	readonly createdAt: Date;

	/** Last successful registration or refresh time. */
	readonly lastSeenAt: Date;

	/** Last push-token rotation time. */
	readonly pushTokenUpdatedAt: Date;

	/** Time at which the installation was disabled. */
	readonly disabledAt: Date | null;
};

/** Firestore representation of a registered mobile installation. */
export type StoredMobileInstallation = Rest & Omit<
	MobileInstallation,
	| 'id'
	| 'createdAt'
	| 'lastSeenAt'
	| 'pushTokenUpdatedAt'
	| 'disabledAt'
> & {
	/** Last successful registration or refresh time. */
	readonly lastSeen: Date;

	/** Last push-token rotation time. */
	readonly pushTokenUpdated: Date;

	/** Time at which the installation was disabled. */
	readonly disabled: Date | null;
};

/** Input supplied by an authenticated mobile application during registration. */
export type RegisterMobileInstallationInput = {
	/** Firebase user owning the mobile installation. */
	readonly userId: string;

	/** Stable identifier generated by the mobile application installation. */
	readonly mobileInstallationId: string;

	/** Installed Assosync mobile application. */
	readonly mobileApplicationId: MobileApplicationId;

	/** Operating system running the mobile application. */
	readonly platform: MobilePlatform;

	/** Optional user-facing mobile device name. */
	readonly mobileDeviceName?: string | null;

	/** Optional installed mobile application version. */
	readonly mobileApplicationVersion?: string | null;

	/** Current Firebase Cloud Messaging registration token. */
	readonly pushToken: string;
};

/** Safe mobile installation representation exposed outside server infrastructure. */
export type PublicMobileInstallation = Omit<
	MobileInstallation,
	'userId' | 'pushToken' | 'pushTokenHash'
>;

/** Persists account-scoped mobile application installations. */
export type MobileInstallationRepository = {
	/**
	 * Creates or refreshes a mobile installation atomically.
	 * @param mobileInstallation - Complete mobile installation state.
	 * @returns The persisted mobile installation.
	 */
	readonly upsert: (mobileInstallation: MobileInstallation) => Promise<MobileInstallation>;

	/**
	 * Finds a mobile installation owned by an account.
	 * @param userId - Firebase user owning the mobile installation.
	 * @param mobileInstallationId - Mobile installation identifier.
	 * @returns The matching mobile installation or null.
	 */
	readonly findById: (userId: string, mobileInstallationId: string) => Promise<MobileInstallation | null>;

	/**
	 * Lists active mobile installations available for authentication approval.
	 * @param userId - Firebase user owning the mobile installations.
	 * @returns The active mobile installations.
	 */
	readonly listActiveByUser: (userId: string) => Promise<readonly MobileInstallation[]>;

	/**
	 * Disables a mobile installation atomically.
	 * @param userId - Firebase user owning the mobile installation.
	 * @param mobileInstallationId - Mobile installation identifier.
	 * @param disabledAt - Disable time.
	 * @returns The disabled mobile installation or null.
	 */
	readonly disable: (userId: string, mobileInstallationId: string, disabledAt: Date) => Promise<MobileInstallation | null>;
};

/** Input used to notify every active mobile installation owned by an account. */
export type SendMobilePushNotificationInput = {
	/** Firebase user owning the target mobile installations. */
	readonly userId: string;

	/** Localized visible notification content. */
	readonly notification: FirebaseCloudMessagingNotification;

	/** String-only values delivered to the mobile application. */
	readonly data: Readonly<Record<string, string>>;
};

/** Result returned after notifying an account's active mobile installations. */
export type SendMobilePushNotificationResult =
	FirebaseCloudMessagingBatchResult;

/** Next.js context supplied to a single-device account route. */
export type DeviceRouteContext = {
	/** Dynamic route parameters. */
	readonly params: Promise<{
		/** Device identifier extracted from the URL. */
		readonly deviceId: string;
	}>;
};

/** Result returned when a new browser device token is issued. */
export type IssuedDevice = {
	/** Persisted device record. */
	readonly device: Device;

	/** Raw secret to place in the device cookie. */
	readonly token: string;
};

/** Input used after successful primary authentication. */
export type PrepareDeviceLoginInput = {
	/** Existing raw device cookie value, when available. */
	readonly deviceToken: string | null;

	/** Authenticated Firebase user identifier. */
	readonly userId: string;

	/** Application owning the authentication flow. */
	readonly applicationId: string;

	/** Optional label used when creating a device. */
	readonly displayName?: string | null;

	/** Information derived from the incoming browser request. */
	readonly detectedInformation: DetectedDeviceInformation;
};

/** Decision returned after applying the trusted-device gate. */
export type DeviceLoginDecision =
	| {
		/** A session may be issued immediately. */
		readonly status: 'session_ready';

		/** Existing verified device. */
		readonly device: Device;

		/** No replacement device cookie is required. */
		readonly issuedDeviceToken: null;
	}
	| {
		/** The application must request device verification. */
		readonly status: 'verification_required';

		/** Pending device awaiting confirmation. */
		readonly device: Device;

		/** New cookie token, or null when the existing cookie remains valid. */
		readonly issuedDeviceToken: string | null;
	};

/** Supported device confirmation channels. */
export type DeviceVerificationMode =
	| 'email_code'
	| 'mobile_approval';

/** Server-side lifecycle of a device verification. */
export type DeviceVerificationStatus =
	| 'pending'
	| 'approved'
	| 'rejected'
	| 'finalizing'
	| 'consumed';

/** Represents a short-lived device verification. */
export type DeviceVerification = {
	/** Unique opaque verification identifier. */
	readonly id: string;

	/** Firebase user owning the verification. */
	readonly userId: string;

	/** Application owning the authentication flow. */
	readonly applicationId: string;

	/** Pending device identifier. */
	readonly deviceId: string;

	/** Selected confirmation channel. */
	readonly mode: DeviceVerificationMode;

	/** Hash of the browser-only continuation secret. */
	readonly browserTokenHash: string;

	/** Keyed hash of the email verification code. */
	readonly codeHash: string | null;

	/** Hash of the mobile approval token. */
	readonly approvalTokenHash: string | null;

	/** Current verification lifecycle state. */
	readonly status: DeviceVerificationStatus;

	/** Number of failed email code attempts. */
	readonly failedAttempts: number;

	/** Maximum number of failed email code attempts. */
	readonly maxAttempts: number;

	/** Number of replacement email codes already issued. */
	readonly emailResendCount: number;

	/** Last time an email verification code was issued. */
	readonly emailLastSentAt: Date | null;

	/** Verification creation time. */
	readonly createdAt: Date;

	/** Verification expiration time. */
	readonly expiresAt: Date;

	/** Verification approval time. */
	readonly approvedAt: Date | null;

	/** Verification rejection time. */
	readonly rejectedAt: Date | null;

	/** Time at which persistent device finalization started. */
	readonly finalizingAt: Date | null;

	/** Verification consumption time. */
	readonly consumedAt: Date | null;
};

/** Redis representation of a short-lived device verification. */
export type StoredDeviceVerification = Omit<
	DeviceVerification,
	| 'createdAt'
	| 'expiresAt'
	| 'emailLastSentAt'
	| 'approvedAt'
	| 'rejectedAt'
	| 'finalizingAt'
	| 'consumedAt'
> & {
	/** ISO-8601 verification creation time. */
	readonly createdAt: string;

	/** ISO-8601 verification expiration time. */
	readonly expiresAt: string;

	/** ISO-8601 time of the latest email code issuance. */
	readonly emailLastSentAt: string | null;

	/** ISO-8601 approval time. */
	readonly approvedAt: string | null;

	/** ISO-8601 rejection time. */
	readonly rejectedAt: string | null;

	/** ISO-8601 finalization start time. */
	readonly finalizingAt: string | null;

	/** ISO-8601 consumption time. */
	readonly consumedAt: string | null;
};

/** Result of an atomic email code attempt. */
export type EmailCodeAttemptResult =
	| {
	/** The code was valid and the verification was approved. */
	readonly outcome: 'approved';

	/** Approved verification state. */
	readonly verification: DeviceVerification;
}
	| {
	/** The supplied code was invalid. */
	readonly outcome: 'invalid';

	/** Remaining attempts before the verification is locked. */
	readonly remainingAttempts: number;
}
	| {
	/** The verification no longer exists. */
	readonly outcome: 'not_found';
}
	| {
	/** The verification expired. */
	readonly outcome: 'expired';
}
	| {
	/** The maximum number of attempts was reached. */
	readonly outcome: 'locked';

	/** Whether this attempt caused the verification to become locked. */
	readonly newlyLocked: boolean;
};

/** Input for an atomic email code attempt. */
export type EmailCodeAttemptInput = {
	/** Firebase user owning the verification. */
	readonly userId: string;

	/** Verification identifier. */
	readonly verificationId: string;

	/** Hash of the browser continuation secret. */
	readonly browserTokenHash: string;

	/** Keyed hash of the submitted email code. */
	readonly codeHash: string;

	/** Expected application identifier. */
	readonly applicationId: string;

	/** Attempt time. */
	readonly attemptedAt: Date;
};

/** Input for atomically replacing an email verification code. */
export type ResendEmailCodeInput = {
	/** Firebase user owning the verification. */
	readonly userId: string;

	/** Verification identifier. */
	readonly verificationId: string;

	/** Expected application identifier. */
	readonly applicationId: string;

	/** Expected pending browser device identifier. */
	readonly deviceId: string;

	/** Hash of the browser-only continuation secret. */
	readonly browserTokenHash: string;

	/** Hash of the newly generated email code. */
	readonly codeHash: string;

	/** Time at which the replacement code is issued. */
	readonly sentAt: Date;

	/** New verification expiration time. */
	readonly expiresAt: Date;

	/** Minimum duration between email code sends. */
	readonly cooldownMs: number;

	/** Maximum number of replacement codes. */
	readonly maxResends: number;
};

/** Result of an atomic email verification code replacement. */
export type ResendEmailCodeResult =
	| {
		/** A replacement code was persisted. */
		readonly outcome: 'resent';

		/** Updated verification state. */
		readonly verification: DeviceVerification;
	}
	| {
		/** The caller must wait before requesting another code. */
		readonly outcome: 'cooldown';

		/** Remaining wait duration in milliseconds. */
		readonly retryAfterMs: number;
	}
	| {
		/** The maximum number of replacement codes was reached. */
		readonly outcome: 'limit_reached';
	}
	| {
		/** The verification is absent, expired, or does not match. */
		readonly outcome: 'not_found';
	};

/** Input for completing or rolling back a reserved email resend. */
export type EmailCodeResendTransitionInput = {
	/** Firebase user owning the verification. */
	readonly userId: string;

	/** Verification identifier. */
	readonly verificationId: string;

	/** Expected application identifier. */
	readonly applicationId: string;

	/** Expected pending browser device identifier. */
	readonly deviceId: string;

	/** Hash of the browser continuation secret. */
	readonly browserTokenHash: string;

	/** Hash of the reserved replacement code. */
	readonly codeHash: string;
};

/** Input for atomically cancelling an email verification. */
export type CancelEmailVerificationRepositoryInput = {
	/** Firebase user owning the verification. */
	readonly userId: string;

	/** Verification identifier. */
	readonly verificationId: string;

	/** Expected application identifier. */
	readonly applicationId: string;

	/** Expected pending browser device identifier. */
	readonly deviceId: string;

	/** Hash of the browser-only continuation secret. */
	readonly browserTokenHash: string;
};

/** Input for an atomic mobile approval. */
export type MobileApprovalInput = {
	/** Firebase user approving the verification. */
	readonly userId: string;

	/** Verification identifier included in the approval payload. */
	readonly verificationId: string;

	/** Hash of the mobile approval token. */
	readonly approvalTokenHash: string;

	/** Expected application identifier. */
	readonly applicationId: string;

	/** Approval time. */
	readonly approvedAt: Date;
};

/** Input for securely resolving a mobile approval request. */
export type ResolveMobileApprovalInput = {
	/** Firebase user owning the verification. */
	readonly userId: string;

	/** Verification identifier delivered through the notification. */
	readonly verificationId: string;

	/** Hash of the secret delivered through the notification. */
	readonly approvalTokenHash: string;

	/** Resolution time used to reject expired requests. */
	readonly resolvedAt: Date;
};

/** Input for securely reading mobile approval state from the browser. */
export type ResolveBrowserMobileVerificationInput = {
	/** Firebase user owning the verification. */
	readonly userId: string;

	/** Verification identifier returned to the browser. */
	readonly verificationId: string;

	/** Expected application identifier. */
	readonly applicationId: string;

	/** Expected pending browser device identifier. */
	readonly deviceId: string;

	/** Hash of the browser-only continuation secret. */
	readonly browserTokenHash: string;

	/** Resolution time used to reject expired requests. */
	readonly resolvedAt: Date;
};

/** Input for atomically rejecting a pending mobile approval. */
export type RejectMobileApprovalInput = {
	/** Firebase user rejecting the verification. */
	readonly userId: string;

	/** Verification identifier delivered through the notification. */
	readonly verificationId: string;

	/** Hash of the secret delivered through the notification. */
	readonly approvalTokenHash: string;

	/** Rejection time. */
	readonly rejectedAt: Date;
};

/** Input for atomically beginning persistent device finalization. */
export type BeginDeviceVerificationFinalizationInput = {
	/** Firebase user owning the verification. */
	readonly userId: string;

	/** Verification identifier. */
	readonly verificationId: string;

	/** Browser continuation secret hash. */
	readonly browserTokenHash: string;

	/** Expected application identifier. */
	readonly applicationId: string;

	/** Expected device identifier. */
	readonly deviceId: string;

	/** Finalization start time. */
	readonly finalizingAt: Date;

	/** Minimum Redis lifetime retained for recovery. */
	readonly recoveryLifetimeMs: number;
};

/** Input for atomically completing persistent device finalization. */
export type CompleteDeviceVerificationFinalizationInput = {
	/** Firebase user owning the verification. */
	readonly userId: string;

	/** Verification identifier. */
	readonly verificationId: string;

	/** Browser continuation secret hash. */
	readonly browserTokenHash: string;

	/** Expected application identifier. */
	readonly applicationId: string;

	/** Expected device identifier. */
	readonly deviceId: string;

	/** Completion time. */
	readonly consumedAt: Date;

	/** Minimum Redis lifetime retained for idempotent retries. */
	readonly recoveryLifetimeMs: number;
};

/** Persists short-lived device verifications. */
export type DeviceVerificationRepository = {
	/**
	 * Creates a verification with a Redis TTL matching its expiration.
	 * @param verification - Verification to persist.
	 * @returns The persisted verification.
	 */
	readonly create: (verification: DeviceVerification) => Promise<DeviceVerification>;

	/**
	 * Checks an email code and increments failures atomically.
	 * @param input - Bound email code attempt.
	 * @returns The atomic attempt result.
	 */
	readonly attemptEmailCode: (input: EmailCodeAttemptInput) => Promise<EmailCodeAttemptResult>;

	/**
	 * Replaces an email verification code atomically.
	 * @param input - Bound replacement code request.
	 * @returns The atomic replacement outcome.
	 */
	readonly resendEmailCode: (input: ResendEmailCodeInput) => Promise<ResendEmailCodeResult>;

	/**
	 * Commits a successfully delivered replacement email code.
	 * @param input - Bound resend transition.
	 * @returns Whether the matching reservation was completed.
	 */
	readonly completeEmailCodeResend: (input: EmailCodeResendTransitionInput) => Promise<boolean>;

	/**
	 * Restores the previous email code after delivery failure.
	 * @param input - Bound resend transition.
	 * @returns Whether the matching reservation was rolled back.
	 */
	readonly rollbackEmailCodeResend: (input: EmailCodeResendTransitionInput) => Promise<boolean>;

	/**
	 * Cancels an email verification atomically.
	 * @param input - Bound cancellation request.
	 * @returns Whether a matching verification was removed.
	 */
	readonly cancelEmail: (input: CancelEmailVerificationRepositoryInput) => Promise<boolean>;

	/**
	 * Approves a pending mobile verification atomically.
	 * @param input - Bound mobile approval.
	 * @returns The approved verification or null.
	 */
	readonly approveMobile: (input: MobileApprovalInput) => Promise<DeviceVerification | null>;

	/**
	 * Resolves a pending mobile verification using its approval secret.
	 * @param input - Bound mobile approval lookup.
	 * @returns The matching verification or null.
	 */
	readonly resolveMobileApproval: (input: ResolveMobileApprovalInput) => Promise<DeviceVerification | null>;

	/**
	 * Resolves mobile verification state using the browser continuation secret.
	 * @param input - Bound browser verification lookup.
	 * @returns The matching verification or null.
	 */
	readonly resolveBrowserMobileVerification: (input: ResolveBrowserMobileVerificationInput) => Promise<DeviceVerification | null>;

	/**
	 * Rejects a pending mobile verification atomically.
	 * @param input - Bound mobile rejection.
	 * @returns The rejected verification or null.
	 */
	readonly rejectMobile: (input: RejectMobileApprovalInput) => Promise<DeviceVerification | null>;

	/**
	 * Begins a recoverable persistent device finalization.
	 * @param input - Bound finalization request.
	 * @returns The finalizing verification or null.
	 */
	readonly beginFinalization: (input: BeginDeviceVerificationFinalizationInput) => Promise<DeviceVerification | null>;

	/**
	 * Completes a persistent device finalization idempotently.
	 * @param input - Bound finalization completion.
	 * @returns The consumed verification or null.
	 */
	readonly completeFinalization: (input: CompleteDeviceVerificationFinalizationInput) => Promise<DeviceVerification | null>;
};

/** Settings controlling device verification behavior. */
export type DeviceVerificationServiceOptions = {
	/** Verification lifetime in milliseconds. */
	readonly lifetimeMs: number;

	/** Maximum number of failed email code attempts. */
	readonly maxEmailAttempts: number;

	/** Maximum number of replacement email codes. */
	readonly maxEmailResends: number;

	/** Minimum duration between email code sends in milliseconds. */
	readonly emailResendCooldownMs: number;

	/** Minimum Redis lifetime retained while finalization is recoverable. */
	readonly finalizationRecoveryMs: number;
};

/** Common input for starting a device verification. */
export type StartDeviceVerificationInput = {
	/** Firebase user owning the pending device. */
	readonly userId: string;

	/** Application owning the authentication flow. */
	readonly applicationId: string;

	/** Pending device identifier. */
	readonly deviceId: string;
};

/** Resolves confirmation modes available to an authenticated user. */
export type DeviceVerificationModePolicy = {
	/**
	 * Resolves allowed confirmation modes.
	 * @param input - Pending device identity.
	 * @returns The available confirmation modes.
	 */
	readonly getAvailableModes: (input: ResolveDeviceVerificationModesInput) => Promise<readonly DeviceVerificationMode[]>;
};

/** Identity used to resolve available device verification channels. */
export type ResolveDeviceVerificationModesInput = {
	/** Firebase user owning the authentication flow. */
	readonly userId: string;

	/** Application requesting authentication. */
	readonly applicationId: string;
};

/** Values issued for an email code verification. */
export type IssuedEmailDeviceVerification = {
	/** Persisted verification. */
	readonly verification: DeviceVerification;

	/** Raw secret to store in a temporary HttpOnly browser cookie. */
	readonly browserToken: string;

	/** One-time code to send to the verified email address. */
	readonly emailCode: string;
};

/** Values issued for a mobile approval verification. */
export type IssuedMobileDeviceVerification = {
	/** Persisted verification. */
	readonly verification: DeviceVerification;

	/** Raw secret to store in a temporary HttpOnly browser cookie. */
	readonly browserToken: string;

	/** Token delivered to the authenticated mobile application. */
	readonly approvalToken: string;
};

/** Input used to confirm an email verification code. */
export type ConfirmEmailCodeInput = {
	/** Firebase user owning the verification. */
	readonly userId: string;

	/** Verification identifier. */
	readonly verificationId: string;

	/** Raw browser continuation secret. */
	readonly browserToken: string;

	/** User-entered six-digit code. */
	readonly code: string;

	/** Expected application identifier. */
	readonly applicationId: string;

	/** Expected pending browser device identifier. */
	readonly deviceId: string;
};

/** Input used to request a replacement email verification code. */
export type ResendEmailVerificationInput = {
	/** Firebase user owning the verification. */
	readonly userId: string;

	/** Verification identifier. */
	readonly verificationId: string;

	/** Browser continuation secret stored in a temporary cookie. */
	readonly browserToken: string;

	/** Expected application identifier. */
	readonly applicationId: string;

	/** Expected pending browser device identifier. */
	readonly deviceId: string;
};

/** Input used to cancel an email device verification. */
export type CancelEmailVerificationInput =
	ResendEmailVerificationInput;

/** Input used to complete an approved device verification. */
export type CompleteDeviceVerificationInput = {
	/** Firebase user owning the verification. */
	readonly userId: string;

	/** Verification identifier. */
	readonly verificationId: string;

	/** Raw browser continuation secret. */
	readonly browserToken: string;

	/** Expected application identifier. */
	readonly applicationId: string;

	/** Expected pending device identifier. */
	readonly deviceId: string;
};

/** Input used by an authenticated mobile application to approve a device. */
export type ApproveMobileVerificationInput = {
	/** Firebase user owning the verification. */
	readonly userId: string;

	/** Verification identifier displayed by the browser. */
	readonly verificationId: string;

	/** Raw approval token displayed by the browser. */
	readonly approvalToken: string;

	/** Expected application identifier. */
	readonly applicationId: string;
};

/** Mobile response supported by an authentication approval request. */
export type MobileApprovalDecision = 'approve' | 'reject';

/** Input used by a registered mobile installation to inspect an approval. */
export type GetMobileApprovalRequestInput = {
	/** Firebase user owning the verification. */
	readonly userId: string;

	/** Registered mobile installation identifier. */
	readonly mobileInstallationId: string;

	/** Verification identifier delivered through the notification. */
	readonly verificationId: string;

	/** Raw approval secret delivered through the notification. */
	readonly approvalToken: string;
};

/** Safe context displayed by a future mobile approval BottomSheet. */
export type MobileApprovalRequest = {
	/** Verification identifier. */
	readonly verificationId: string;

	/** Application requesting authentication. */
	readonly applicationId: string;

	/** Pending browser device identifier. */
	readonly deviceId: string;

	/** Best currently available browser device label. */
	readonly deviceDisplayName: string | null;

	/** Coarse category of the browser device. */
	readonly deviceCategory: DeviceCategory;

	/** Detected browser family. */
	readonly browserName: string | null;

	/** Detected browser version. */
	readonly browserVersion: string | null;

	/** Detected operating system family. */
	readonly operatingSystemName: string | null;

	/** Detected operating system version. */
	readonly operatingSystemVersion: string | null;

	/** Reasonably detected device brand. */
	readonly deviceBrand: string | null;

	/** Device model reported through Client Hints. */
	readonly deviceModel: string | null;

	/** Current approval state displayed by the mobile application. */
	readonly status: 'pending' | 'approved' | 'rejected';

	/** Verification creation time. */
	readonly createdAt: Date;

	/** Verification expiration time. */
	readonly expiresAt: Date;
};

/** Input used by a registered mobile installation to answer an approval. */
export type RespondMobileApprovalInput =
	GetMobileApprovalRequestInput & {
		/** Explicit user decision from the mobile application. */
		readonly decision: MobileApprovalDecision;
	};

/** Input used by the browser to inspect its mobile verification state. */
export type GetBrowserMobileVerificationInput = {
	/** Firebase user owning the verification. */
	readonly userId: string;

	/** Verification identifier returned to the browser. */
	readonly verificationId: string;

	/** Browser-only continuation secret. */
	readonly browserToken: string;

	/** Expected application identifier. */
	readonly applicationId: string;

	/** Expected pending browser device identifier. */
	readonly deviceId: string;
};

/** Next.js context supplied to a mobile approval request route. */
export type MobileApprovalRouteContext = {
	/** Dynamic route parameters. */
	readonly params: Promise<{
		/** Verification identifier extracted from the URL. */
		readonly verificationId: string;
	}>;
};

/** Product identities supported by the verification email template. */
export type VerificationEmailType =
	| 'assosync'
	| 'calendis'
	| 'collectineo';

/** Configures the verification email identity of one application. */
export type VerificationEmailBrand = {
	/** Authentication application identifier. */
	readonly applicationId: string;

	/** Product identity rendered by the email template. */
	readonly emailType: VerificationEmailType;

	/** User-facing application name used in the subject. */
	readonly displayName: string;

	/** Verified sender address. */
	readonly from: string;

	/** Optional reply-to address. */
	readonly replyTo?: string;
};

/** Configures device verification email composition. */
export type VerificationEmailServiceOptions = {
	/** Application-specific sender configurations. */
	readonly brands: readonly VerificationEmailBrand[];
};

/** Input used to send a generated device verification code. */
export type SendVerificationEmailInput = {
	/** Values generated and persisted by the verification service. */
	readonly issued: IssuedEmailDeviceVerification;

	/** Verified email address from the Firebase identity. */
	readonly to: string;

	/** Recipient first name displayed by the template. */
	readonly firstname?: string;
};

/** Email operation required by device verification. */
export type VerificationEmailSender = Pick<
	Mailer,
	'send'
>;

/** Result returned after the provider accepts an email. */
export type VerificationEmailResult = SentMail;

/** Authentication event categories producing a security warning email. */
export type AuthWarningTrigger =
	| 'mobile_approval_rejected'
	| 'verification_locked'
	| 'verification_rate_limited';

/** Safe context required to emit one authentication warning. */
export type SendAuthWarningInput = {
	/** Firebase user receiving the warning. */
	readonly userId: string;

	/** Application in which the authentication attempt occurred. */
	readonly applicationId: string;

	/** Pending browser device associated with the attempt. */
	readonly deviceId: string;

	/** Verification identifier used to deduplicate warning delivery. */
	readonly verificationId: string | null;

	/** Security signal responsible for the warning. */
	readonly trigger: AuthWarningTrigger;

	/** Time at which the suspicious signal occurred. */
	readonly occurredAt: Date;

	/** Optional penalty level used to distinguish progressive restrictions. */
	readonly penaltyLevel: number | null;
};

/** Best-effort authentication warning delivery contract. */
export type AuthWarningNotifier = {
	/**
	 * Sends a deduplicated security warning without exposing delivery failures.
	 * @param input - Safe authentication warning context.
	 * @returns A promise resolved after the delivery attempt.
	 */
	readonly notify: (input: SendAuthWarningInput) => Promise<void>;
};

/** Resolves an account identity for a server-generated warning. */
export type AuthWarningIdentityProvider = {
	/**
	 * Resolves a Firebase user without requiring a browser token.
	 * @param userId - Firebase user identifier.
	 * @returns The recipient identity and available email state.
	 */
	readonly resolve: (userId: string) => Promise<AuthenticationIdentity>;
};

/** Configures security warning email composition. */
export type AuthWarningEmailServiceOptions = {
	/** Trusted Assosync Account security page. */
	readonly securityUrl: string;

	/** Application-specific sender configurations. */
	readonly brands: readonly VerificationEmailBrand[];
};

/** Identity extracted from a verified Firebase session. */
export type VerifiedFirebaseSession = {
	/** Firebase user identifier. */
	readonly userId: string;

	/** Firebase session expiration time. */
	readonly expiresAt: Date;
};

/** Values returned after creating a Firebase session cookie. */
export type CreatedFirebaseSession = {
	/** Signed Firebase session cookie. */
	readonly cookie: string;

	/** Identity represented by the session cookie. */
	readonly identity: VerifiedFirebaseSession;
};

/** Creates and verifies Firebase session cookies. */
export type FirebaseSessionAdapter = {
	/**
	 * Exchanges a recent Firebase ID token for a session cookie.
	 * @param idToken - Fresh Firebase ID token.
	 * @param expiresInMs - Requested session lifetime in milliseconds.
	 * @returns The signed cookie and its verified identity.
	 */
	readonly create: (idToken: string, expiresInMs: number) => Promise<CreatedFirebaseSession>;

	/**
	 * Verifies a signed Firebase session cookie.
	 * @param sessionCookie - Signed Firebase session cookie.
	 * @param checkRevoked - Whether Firebase revocation must be checked.
	 * @returns The verified Firebase identity.
	 */
	readonly verify: (sessionCookie: string, checkRevoked: boolean) => Promise<VerifiedFirebaseSession>;
};

/** Minimal decoded Firebase token required by the session adapter. */
export type FirebaseDecodedSession = {
	/** Firebase user identifier. */
	readonly uid: string;

	/** Token expiration time expressed as Unix seconds. */
	readonly exp: number;

	/** Authentication time expressed as Unix seconds. */
	readonly auth_time?: number;
};

/** Minimal Firebase Admin Auth contract required by the session adapter. */
export type FirebaseAdminSessionProvider = {
	/**
	 * Verifies a Firebase ID token.
	 * @param idToken - Firebase ID token.
	 * @param checkRevoked - Whether revocation must be checked.
	 * @returns The decoded token.
	 */
	readonly verifyIdToken: (idToken: string, checkRevoked?: boolean) => Promise<FirebaseDecodedSession>;

	/**
	 * Creates a signed Firebase session cookie.
	 * @param idToken - Verified Firebase ID token.
	 * @param options - Cookie expiration settings.
	 * @returns The signed Firebase cookie.
	 */
	readonly createSessionCookie: (
		idToken: string,
		options: {
			readonly expiresIn: number;
		}
	) => Promise<string>;

	/**
	 * Verifies a signed Firebase session cookie.
	 * @param sessionCookie - Signed Firebase session cookie.
	 * @param checkRevoked - Whether revocation must be checked.
	 * @returns The decoded session.
	 */
	readonly verifySessionCookie: (sessionCookie: string, checkRevoked?: boolean) => Promise<FirebaseDecodedSession>;
};

/** Represents one revocable application session. */
export type Session = {
	/** Internal opaque session identifier. */
	readonly id: string;

	/** Hash of the token stored in the connection cookie. */
	readonly tokenHash: string;

	/** Firebase user owning the session. */
	readonly userId: string;

	/** Trusted browser device associated with the session. */
	readonly deviceId: string;

	/** Application owning the session. */
	readonly applicationId: string;

	/** Session creation time. */
	readonly createdAt: Date;

	/** Session expiration time. */
	readonly expiresAt: Date;

	/** Last successful session use time. */
	readonly lastSeenAt: Date;

	/** Session revocation time. */
	readonly revokedAt: Date | null;
};

/** Firestore representation of an application session. */
export type StoredSession = Rest & Omit<
	Session,
	'id' | 'createdAt' | 'expiresAt' | 'lastSeenAt' | 'revokedAt'
> & {
	/** Session expiration time. */
	readonly expires: Date;

	/** Last successful session use time. */
	readonly lastSeen: Date;

	/** Session revocation time. */
	readonly revoked: Date | null;
};

/** Session fields required before Firestore assigns the document identifier. */
export type CreateSessionInput = Omit<Session, 'id'>;

/** Public account representation of an application session. */
export type AccountSession = Omit<
	Session,
	'tokenHash' | 'userId'
> & {
	/** Whether this is the session making the request. */
	readonly isCurrent: boolean;

	/** Whether the session can still authenticate requests. */
	readonly isActive: boolean;
};

/** Next.js context supplied to a single-session account route. */
export type SessionRouteContext = {
	/** Dynamic route parameters. */
	readonly params: Promise<{
		/** Session identifier extracted from the URL. */
		readonly sessionId: string;
	}>;
};

/** Persists account-scoped application sessions. */
export type SessionRepository = {
	/**
	 * Creates an application session.
	 * @param session - Session to persist.
	 * @returns The persisted session.
	 */
	readonly create: (session: CreateSessionInput) => Promise<Session>;

	/**
	 * Finds a session from its hashed connection token.
	 * @param userId - Firebase user owning the session collection.
	 * @param tokenHash - Hash of the connection cookie token.
	 * @param applicationId - Expected application identifier.
	 * @returns The matching session or null.
	 */
	readonly findByTokenHash: (userId: string, tokenHash: string, applicationId: string) => Promise<Session | null>;

	/**
	 * Lists every session owned by an account.
	 * @param userId - Firebase user owning the session collection.
	 * @returns The account sessions.
	 */
	readonly listByUser: (userId: string) => Promise<readonly Session[]>;

	/**
	 * Atomically marks an active session as recently used.
	 * @param userId - Firebase user owning the session.
	 * @param sessionId - Internal session identifier.
	 * @param applicationId - Expected application identifier.
	 * @param seenAt - Successful verification time.
	 * @returns The updated session or null when it is no longer active.
	 */
	readonly touchActive: (userId: string, sessionId: string, applicationId: string, seenAt: Date) => Promise<Session | null>;

	/**
	 * Atomically revokes an application session.
	 * @param userId - Firebase user owning the session.
	 * @param sessionId - Internal session identifier.
	 * @param applicationId - Expected application identifier.
	 * @param revokedAt - Revocation time.
	 * @returns The revoked session or null when it does not exist.
	 */
	readonly revoke: (userId: string, sessionId: string, applicationId: string, revokedAt: Date) => Promise<Session | null>;

	/**
	 * Revokes every active session associated with a device.
	 * @param userId - Firebase user owning the sessions.
	 * @param deviceId - Device whose sessions must be revoked.
	 * @param revokedAt - Revocation time.
	 * @returns The number of sessions revoked.
	 */
	readonly revokeByDevice: (userId: string, deviceId: string, revokedAt: Date) => Promise<number>;

	/**
	 * Revokes one account-owned session without trusting its application.
	 * @param userId - Firebase user owning the session.
	 * @param sessionId - Session identifier.
	 * @param revokedAt - Revocation time.
	 * @returns The revoked session or null when it does not exist.
	 */
	readonly revokeOwned: (userId: string, sessionId: string, revokedAt: Date) => Promise<Session | null>;

	/**
	 * Revokes every active account session except the current one.
	 * @param userId - Firebase user owning the sessions.
	 * @param currentSessionId - Session that must remain active.
	 * @param revokedAt - Revocation time.
	 * @returns The number of sessions revoked.
	 */
	readonly revokeOthers: (userId: string, currentSessionId: string, revokedAt: Date) => Promise<number>;
};

/** Values issued for a new authenticated session. */
export type IssuedSession = {
	/** Persisted application session. */
	readonly session: Session;

	/** Secret to place in the application connection cookie. */
	readonly sessionToken: string;

	/** Signed Firebase session cookie. */
	readonly firebaseSessionCookie: string;
};

/** Input used to issue an authenticated session. */
export type IssueSessionInput = {
	/** Fresh Firebase ID token. */
	readonly idToken: string;

	/** Trusted browser device identifier. */
	readonly deviceId: string;

	/** Raw token read from the device cookie. */
	readonly deviceToken: string;

	/** Application owning the session. */
	readonly applicationId: string;
};

/** Input used to verify an authenticated session. */
export type VerifySessionInput = {
	/** Signed Firebase session cookie. */
	readonly firebaseSessionCookie: string;

	/** Raw application connection token. */
	readonly sessionToken: string;

	/** Expected application identifier. */
	readonly applicationId: string;

	/** Whether Firebase revocation must be checked. */
	readonly checkFirebaseRevocation?: boolean;
};

/** Input used to revoke an application session. */
export type RevokeSessionInput = {
	/** Firebase user owning the session. */
	readonly userId: string;

	/** Internal application session identifier. */
	readonly sessionId: string;

	/** Expected application identifier. */
	readonly applicationId: string;
};

/** Session security settings. */
export type SessionServiceOptions = {
	/** Session lifetime in milliseconds. */
	readonly lifetimeMs: number;
};

/** Firebase session adapter security settings. */
export type FirebaseSessionAdapterOptions = {
	/** Maximum accepted age of the ID token authentication event. */
	readonly maxAuthenticationAgeMs: number;
};

/** Verified Firebase identity used by the authentication workflow. */
export type AuthenticationIdentity = {
	/** Firebase user identifier. */
	readonly userId: string;

	/** Firebase email address used by authentication messages. */
	readonly email: string;

	/** Whether Firebase currently considers the email address verified. */
	readonly emailVerified: boolean;

	/** First name used in transactional emails. */
	readonly firstname?: string;
};

/** Verifies and updates primary Firebase authentication identities. */
export type AuthenticationIdentityProvider = {
	/**
	 * Verifies a Firebase ID token and resolves its user.
	 * @param idToken - Firebase ID token supplied by the client.
	 * @returns The verified authentication identity.
	 */
	readonly verify: (idToken: string) => Promise<AuthenticationIdentity>;

	/**
	 * Marks the current Firebase email address as verified.
	 * @param userId - Firebase user identifier.
	 * @returns A promise resolved after the account update.
	 */
	readonly markEmailVerified: (userId: string) => Promise<void>;
};

/** Input used to begin authentication after Firebase sign-in. */
export type StartAuthenticationInput = {
	/** Fresh Firebase ID token. */
	readonly idToken: string;

	/** Application owning the authentication flow. */
	readonly applicationId: string;

	/** Existing raw device cookie token. */
	readonly deviceToken: string | null;

	/** Optional user-facing browser device name. */
	readonly deviceDisplayName?: string | null;

	/** Information derived from trusted request headers. */
	readonly detectedDeviceInformation: DetectedDeviceInformation;

	/** Preferred device verification channel. */
	readonly verificationMode?: DeviceVerificationMode;
};

/** Authentication result returned when a session is immediately available. */
export type AuthenticationSessionReady = {
	/** Indicates that authentication is complete. */
	readonly status: 'session_ready';

	/** Newly issued Firebase and application sessions. */
	readonly issuedSession: IssuedSession;
};

/** Authentication result requiring email device confirmation. */
export type AuthenticationVerificationRequired = {
	/** Indicates that device confirmation is required. */
	readonly status: 'verification_required';

	/** Pending browser device identifier. */
	readonly deviceId: string;

	/** Verification identifier safe to return to the browser. */
	readonly verificationId: string;

	/** Browser-only continuation secret. */
	readonly browserToken: string;

	/** Newly issued device token, or null when the existing token remains valid. */
	readonly issuedDeviceToken: string | null;

	/** Verification expiration time. */
	readonly expiresAt: Date;

	/** Confirmation channel selected for this verification. */
	readonly verificationMode: DeviceVerificationMode;
};

/** Decision returned by the authentication workflow. */
export type StartAuthenticationResult =
	| AuthenticationSessionReady
	| AuthenticationVerificationRequired;

/** Input used to confirm email verification and create a session. */
export type CompleteEmailAuthenticationInput = {
	/** Fresh Firebase ID token. */
	readonly idToken: string;

	/** Application owning the authentication flow. */
	readonly applicationId: string;

	/** Pending browser device identifier. */
	readonly deviceId: string;

	/** Raw device cookie token. */
	readonly deviceToken: string;

	/** Verification identifier returned when authentication started. */
	readonly verificationId: string;

	/** Browser continuation secret stored in a temporary cookie. */
	readonly browserToken: string;

	/** Six-digit code entered by the user. */
	readonly code: string;
};

/** Input used to complete mobile approval and create a session. */
export type CompleteMobileAuthenticationInput = {
	/** Fresh Firebase ID token. */
	readonly idToken: string;

	/** Application owning the authentication flow. */
	readonly applicationId: string;

	/** Pending browser device identifier. */
	readonly deviceId: string;

	/** Raw device cookie token. */
	readonly deviceToken: string;

	/** Verification identifier returned when authentication started. */
	readonly verificationId: string;

	/** Browser continuation secret stored in a temporary cookie. */
	readonly browserToken: string;
};

/** Input used to resend or cancel an email authentication verification. */
export type ManageEmailAuthenticationVerificationInput = {
	/** Fresh Firebase ID token. */
	readonly idToken: string;

	/** Application owning the authentication flow. */
	readonly applicationId: string;

	/** Pending browser device identifier. */
	readonly deviceId: string;

	/** Verification identifier returned to the browser. */
	readonly verificationId: string;

	/** Browser continuation secret stored in a temporary cookie. */
	readonly browserToken: string;
};

/** Web applications allowed to use the central Assosync identity service. */
export type WebSsoApplicationId = 'calendis' | 'collectineo';

/** Registered confidential Web client. */
export type WebSsoClient = {
	/** Stable public client identifier. */
	readonly id: WebSsoApplicationId;

	/** Product login URL used to restart an interrupted authorization. */
	readonly loginUri: string;

	/** Product endpoint that consumes an Account-issued flash ticket. */
	readonly authenticationFlashUri: string;

	/** Exact callback URLs accepted for the client. */
	readonly redirectUris: readonly string[];

	/** Exact browser origins allowed to perform passkey ceremonies. */
	readonly passkeyOrigins: readonly string[];

	/** Server-only secret used by the callback exchange. */
	readonly clientSecret: string | undefined;
};

/** Web SSO service security settings. */
export type WebSsoServiceOptions = {
	/** Lifetime of an unfinished browser authorization request. */
	readonly requestLifetimeMs: number;

	/** Lifetime of a single-use authorization code. */
	readonly codeLifetimeMs: number;

	/** Registered Web clients. */
	readonly clients: readonly WebSsoClient[];
};

/** Verified Firebase identity temporarily bound to a Web authorization. */
export type WebAuthorizationIdentity = {
	/** Firebase user identifier verified by Assosync. */
	readonly userId: string | null;

	/** Fresh Firebase ID token required to issue the final session. */
	readonly idToken: string | null;
};

/** One-time identity handoff stored before the Account browser redirect. */
export type StoredWebAuthorizationIdentityTicket = {
	/** Hash of the opaque identity ticket. */
	readonly ticketHash: string;

	/** Web application that authenticated the user. */
	readonly applicationId: WebSsoApplicationId;

	/** Exact callback URL registered by the originating application. */
	readonly redirectUri: string;

	/** Client-generated CSRF correlation value. */
	readonly state: string;

	/** Base64url SHA-256 PKCE challenge. */
	readonly codeChallenge: string;

	/** Firebase identity verified by Assosync. */
	readonly identity: WebAuthorizationIdentity;

	/** ISO ticket creation time. */
	readonly createdAt: string;

	/** ISO ticket expiration time. */
	readonly expiresAt: string;
};

/** Input used by a confidential Web client to create an identity handoff. */
export type IssueWebAuthorizationIdentityInput = {
	/** Registered Web client identifier. */
	readonly applicationId: string;

	/** Registered Web client secret. */
	readonly clientSecret: string;

	/** Exact callback URL used by the browser authorization. */
	readonly redirectUri: string;

	/** Client-generated CSRF correlation value. */
	readonly state: string;

	/** Base64url SHA-256 PKCE challenge. */
	readonly codeChallenge: string;

	/** Fresh Firebase ID token obtained by the product. */
	readonly idToken: string;

	/** Firebase user identifier independently verified by Assosync. */
	readonly userId: string;
};

/** Input used to create a Web authorization before passkey authentication. */
export type IssuePasskeyWebAuthorizationIdentityInput = Omit<
	IssueWebAuthorizationIdentityInput,
	'idToken' | 'userId'
>;

/** Opaque identity handoff returned to a confidential Web client. */
export type IssuedWebAuthorizationIdentityTicket = {
	/** Single-use ticket safe to include in the authorization redirect. */
	readonly ticket: string;

	/** Ticket expiration time. */
	readonly expiresAt: Date;
};

/** Input used to consume a one-time identity handoff. */
export type ConsumeWebAuthorizationIdentityTicketInput = {
	/** Hash of the opaque identity ticket. */
	readonly ticketHash: string;

	/** Current ISO time used for expiration validation. */
	readonly consumedAt: string;
};

/** Pending browser authorization request stored in Redis. */
export type WebAuthorizationRequest = {
	/** Opaque request identifier safe to expose to the browser. */
	readonly id: string;

	/** Target Web application. */
	readonly applicationId: WebSsoApplicationId;

	/** Exact registered callback URL. */
	readonly redirectUri: string;

	/** Client-generated CSRF correlation value. */
	readonly state: string;

	/** Base64url SHA-256 PKCE challenge. */
	readonly codeChallenge: string;

	/** Hash of the browser continuation cookie. */
	readonly browserTokenHash: string;

	/** Firebase identity authenticated by the originating product. */
	readonly identity: WebAuthorizationIdentity;

	/** Request creation time. */
	readonly createdAt: Date;

	/** Request expiration time. */
	readonly expiresAt: Date;
};

/** Serializable Redis representation of a Web authorization request. */
export type StoredWebAuthorizationRequest = Omit<
	WebAuthorizationRequest,
	'createdAt' | 'expiresAt'
> & {
	/** ISO request creation time. */
	readonly createdAt: string;

	/** ISO request expiration time. */
	readonly expiresAt: string;
};

/** Newly created browser authorization request. */
export type IssuedWebAuthorizationRequest = {
	/** Persisted request. */
	readonly request: WebAuthorizationRequest;

	/** Secret bound to the Account browser cookie. */
	readonly browserToken: string;
};

/** Input used by a confidential client to begin an embedded passkey flow. */
export type BeginPasskeyWebAuthorizationInput = IssuePasskeyWebAuthorizationIdentityInput & {
	/** Exact browser origin that will perform the WebAuthn ceremony. */
	readonly passkeyOrigin: string;
};

/** Server-bound passkey authorization returned to a confidential client. */
export type IssuedPasskeyWebAuthorization = IssuedWebAuthorizationRequest & {
	/** Exact trusted origin selected from the registered client configuration. */
	readonly passkeyOrigin: string;
};

/** One-time browser handoff stored before returning to Account. */
export type StoredWebAuthorizationHandoff = {
	/** Hash of the opaque handoff ticket. */
	readonly ticketHash: string;

	/** Active authorization request identifier. */
	readonly requestId: string;

	/** Raw continuation token transferred into an Account-only cookie. */
	readonly browserToken: string;

	/** ISO ticket expiration time. */
	readonly expiresAt: string;
};

/** Input used to consume a browser handoff ticket. */
export type ConsumeWebAuthorizationHandoffInput = {
	/** Hash of the opaque handoff ticket. */
	readonly ticketHash: string;

	/** Current ISO time used for expiration validation. */
	readonly consumedAt: string;
};

/** Opaque browser handoff safe to place in a redirect URL. */
export type IssuedWebAuthorizationHandoff = {
	/** Single-use handoff ticket. */
	readonly ticket: string;

	/** Ticket expiration time. */
	readonly expiresAt: Date;
};

/** Input used to begin Web SSO authorization. */
export type BeginWebAuthorizationInput = {
	/** One-time identity handoff issued to the confidential client. */
	readonly identityTicket: string;
};

/** Serializable session credentials held by a short-lived authorization grant. */
export type StoredIssuedSession = {
	/** Persisted application session with ISO dates. */
	readonly session: Omit<
		Session,
		'createdAt' | 'expiresAt' | 'lastSeenAt' | 'revokedAt'
	> & {
		/** ISO session creation time. */
		readonly createdAt: string;

		/** ISO session expiration time. */
		readonly expiresAt: string;

		/** ISO last-seen time. */
		readonly lastSeenAt: string;

		/** ISO revocation time when revoked. */
		readonly revokedAt: string | null;
	};

	/** Raw application session token. */
	readonly sessionToken: string;

	/** Signed Firebase session cookie. */
	readonly firebaseSessionCookie: string;
};

/** Single-use Web authorization grant stored in Redis. */
export type StoredWebAuthorizationGrant = {
	/** Target Web application. */
	readonly applicationId: WebSsoApplicationId;

	/** Exact registered callback URL. */
	readonly redirectUri: string;

	/** Base64url SHA-256 PKCE challenge. */
	readonly codeChallenge: string;

	/** Client-generated CSRF correlation value. */
	readonly state: string;

	/** One-time application session credentials. */
	readonly issuedSession: StoredIssuedSession;

	/** ISO grant creation time. */
	readonly createdAt: string;

	/** ISO grant expiration time. */
	readonly expiresAt: string;
};

/** Input used to atomically replace a request with an authorization grant. */
export type CompleteWebAuthorizationRepositoryInput = {
	/** Browser authorization request identifier. */
	readonly requestId: string;

	/** Hash of the browser continuation cookie. */
	readonly browserTokenHash: string;

	/** Current ISO time used for expiration validation. */
	readonly completedAt: string;

	/** Grant persisted under its PKCE challenge. */
	readonly grant: StoredWebAuthorizationGrant;

	/** Remaining grant lifetime in milliseconds. */
	readonly grantLifetimeMs: number;
};

/** Input used to consume a Web authorization grant. */
export type ConsumeWebAuthorizationGrantInput = {
	/** Expected Web application. */
	readonly applicationId: WebSsoApplicationId;

	/** Exact callback URL supplied during exchange. */
	readonly redirectUri: string;

	/** PKCE challenge derived from the supplied verifier. */
	readonly codeChallenge: string;

	/** CSRF correlation value retained by the originating Web server. */
	readonly state: string;

	/** Current ISO time used for expiration validation. */
	readonly consumedAt: string;
};

/** Persists temporary Web SSO requests and grants. */
export type WebAuthorizationRepository = {
	/**
	 * Creates a one-time verified identity handoff.
	 * @param ticket - Complete ticket to persist.
	 * @returns A promise resolved after persistence.
	 */
	readonly createIdentityTicket: (ticket: StoredWebAuthorizationIdentityTicket) => Promise<void>;

	/**
	 * Atomically validates and consumes an identity handoff.
	 * @param input - Expected ticket binding and current time.
	 * @returns The consumed ticket or null.
	 */
	readonly consumeIdentityTicket: (input: ConsumeWebAuthorizationIdentityTicketInput) => Promise<StoredWebAuthorizationIdentityTicket | null>;

	/**
	 * Creates a one-time browser handoff.
	 * @param handoff - Complete handoff to persist.
	 * @returns A promise resolved after persistence.
	 */
	readonly createHandoff: (handoff: StoredWebAuthorizationHandoff) => Promise<void>;

	/**
	 * Atomically validates and consumes a browser handoff.
	 * @param input - Expected ticket hash and current time.
	 * @returns The consumed handoff or null.
	 */
	readonly consumeHandoff: (input: ConsumeWebAuthorizationHandoffInput) => Promise<StoredWebAuthorizationHandoff | null>;

	/**
	 * Creates a browser-bound authorization request.
	 * @param request - Complete request to persist.
	 * @returns A promise resolved after persistence.
	 */
	readonly createRequest: (request: WebAuthorizationRequest) => Promise<void>;

	/**
	 * Finds an active browser-bound request.
	 * @param requestId - Opaque request identifier.
	 * @param browserTokenHash - Hash of the browser continuation token.
	 * @param resolvedAt - Current time.
	 * @returns The active request or null.
	 */
	readonly findRequest: (requestId: string, browserTokenHash: string, resolvedAt: Date) => Promise<WebAuthorizationRequest | null>;

	/**
	 * Binds a freshly verified Firebase ID token to a passkey authorization.
	 * @param requestId - Browser authorization request identifier.
	 * @param browserTokenHash - Hash of the browser continuation token.
	 * @param userId - Expected Firebase user identifier.
	 * @param idToken - Fresh Firebase ID token obtained after passkey verification.
	 * @param updatedAt - Current ISO time.
	 * @returns Whether the active request was updated.
	 */
	readonly bindIdentityToken: (requestId: string, browserTokenHash: string, userId: string, idToken: string, updatedAt: string) => Promise<boolean>;

	/**
	 * Binds the account discovered from a verified passkey.
	 * @param requestId - Browser authorization request identifier.
	 * @param browserTokenHash - Hash of the browser continuation token.
	 * @param userId - Firebase user discovered from the credential.
	 * @param updatedAt - Current ISO time.
	 * @returns Whether the active request was updated.
	 */
	readonly bindPasskeyUser: (requestId: string, browserTokenHash: string, userId: string, updatedAt: string) => Promise<boolean>;

	/**
	 * Replaces an active request with a one-time grant.
	 * @param input - Bound request and grant values.
	 * @returns Whether the request was completed.
	 */
	readonly completeRequest: (input: CompleteWebAuthorizationRepositoryInput) => Promise<boolean>;

	/**
	 * Atomically consumes a matching authorization grant.
	 * @param input - Expected client, callback, and PKCE values.
	 * @returns The consumed grant or null.
	 */
	readonly consumeGrant: (input: ConsumeWebAuthorizationGrantInput) => Promise<StoredWebAuthorizationGrant | null>;
};

/** Input used to finalize Web authentication. */
export type CompleteWebAuthorizationInput = {
	/** Browser authorization request identifier. */
	readonly requestId: string;

	/** Raw browser continuation cookie. */
	readonly browserToken: string;

	/** Application session produced by the authentication workflow. */
	readonly issuedSession: IssuedSession;
};

/** Callback destination returned after successful authorization. */
export type CompletedWebAuthorization = {
	/** Exact registered callback URL. */
	readonly redirectUri: string;
};

/** Input used to finalize Web authentication and establish an Account session. */
export type FinalizeWebAuthorizationInput = CompleteWebAuthorizationInput & {
	/** Fresh Firebase ID token used to issue the Account session. */
	readonly idToken: string;

	/** Raw trusted-device token read on the Account domain. */
	readonly deviceToken: string;
};

/** Result of Web authorization with its parallel Account session. */
export type FinalizedWebAuthorization = CompletedWebAuthorization & {
	/** Session issued for the Assosync Account portal. */
	readonly accountSession: IssuedSession;
};

/** Confidential server-to-server Web session exchange input. */
export type ExchangeWebAuthorizationInput = {
	/** Registered Web client identifier. */
	readonly applicationId: string;

	/** Registered Web client secret. */
	readonly clientSecret: string;

	/** PKCE verifier retained by the originating Web server. */
	readonly codeVerifier: string;

	/** CSRF correlation value retained by the originating Web server. */
	readonly state: string;

	/** Exact callback URL used during authorization. */
	readonly redirectUri: string;
};

/** Authentication application resolved from the local host or a Web SSO request. */
export type AuthenticationRequestContext = {
	/** Trusted application identifier used by the authentication workflow. */
	readonly applicationId: string;

	/** Active Web SSO request, or null for a local Account login. */
	readonly webAuthorization: WebAuthorizationRequest | null;
};

/** Properties required by the device confirmation view. */
export type ConfirmDeviceViewProps = {
	/** Active Web authorization identifier. */
	readonly authorizationId: string;

	/** Pending device identifier. */
	readonly deviceId: string;

	/** Active email verification identifier. */
	readonly verificationId: string;

	/** Trusted product login URL used to restart authentication. */
	readonly restartUri: string;
};

/** Email-verification rate-limit settings. */
export type EmailVerificationRateLimitOptions = {
	/** Initial email request window in milliseconds. */
	readonly initialEmailWindowMs: number;

	/** Maximum initial emails allowed during one window. */
	readonly maxInitialEmailsPerWindow: number;

	/** Duration after which the progressive penalty resets. */
	readonly penaltyResetMs: number;

	/** Progressive blocking durations in milliseconds. */
	readonly penaltyDurationsMs: readonly [
		number,
		number,
		number,
		number
	];
};

/** Identity evaluated by the email-verification limiter. */
export type EmailVerificationRateLimitInput = {
	/** Firebase user requesting an email. */
	readonly userId: string;

	/** Application owning the authentication flow. */
	readonly applicationId: string;

	/** Pending browser device related to the request. */
	readonly deviceId: string;

	/** Time of the operation. */
	readonly requestedAt: Date;
};

/** Result returned by the email-verification limiter. */
export type EmailVerificationRateLimitDecision =
	| {
	/** The operation is allowed. */
	readonly allowed: true;
}
	| {
	/** The operation is temporarily blocked. */
	readonly allowed: false;

	/** Remaining blocking time in milliseconds. */
	readonly retryAfterMs: number;

	/** Current progressive penalty level. */
	readonly penaltyLevel: number;

	/** Whether this operation created a new penalty. */
	readonly penaltyApplied: boolean;
};

/** Persists email-verification rate limits in Redis. */
export type EmailVerificationRateLimitRepository = {
	/**
	 * Checks whether an operation is currently blocked.
	 * @param input - Account and application identity.
	 * @returns Current rate-limit decision.
	 */
	readonly check: (input: EmailVerificationRateLimitInput) => Promise<EmailVerificationRateLimitDecision>;

	/**
	 * Reserves one initial verification email.
	 * @param input - Account and application identity.
	 * @returns Current rate-limit decision.
	 */
	readonly reserveInitialEmail: (input: EmailVerificationRateLimitInput) => Promise<EmailVerificationRateLimitDecision>;

	/**
	 * Applies the next progressive penalty.
	 * @param input - Account and application identity.
	 * @returns Applied or existing rate-limit decision.
	 */
	readonly penalize: (input: EmailVerificationRateLimitInput) => Promise<EmailVerificationRateLimitDecision>;
};
