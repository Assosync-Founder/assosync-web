/** Visible notification content sent through Firebase Cloud Messaging. */
export type FirebaseCloudMessagingNotification = {
	/** Localized notification title. */
	readonly title: string;

	/** Localized notification body. */
	readonly body: string;
};

/** One Firebase Cloud Messaging delivery request. */
export type FirebaseCloudMessagingMessage = {
	/** Internal recipient identifier used to correlate the result. */
	readonly recipientId: string;

	/** Firebase Cloud Messaging registration token. */
	readonly token: string;

	/** Optional visible notification content. */
	readonly notification?: FirebaseCloudMessagingNotification;

	/** Optional string-only data delivered to the mobile application. */
	readonly data?: Readonly<Record<string, string>>;
};

/** Successful Firebase Cloud Messaging delivery handoff. */
export type FirebaseCloudMessagingSuccess = {
	/** Internal recipient identifier supplied with the request. */
	readonly recipientId: string;

	/** Successful delivery status. */
	readonly status: 'sent';

	/** Firebase message identifier. */
	readonly messageId: string;
};

/** Failed Firebase Cloud Messaging delivery handoff. */
export type FirebaseCloudMessagingFailure = {
	/** Internal recipient identifier supplied with the request. */
	readonly recipientId: string;

	/** Failed delivery status. */
	readonly status: 'failed';

	/** Firebase error code when available. */
	readonly errorCode: string | null;

	/** Whether the registration token must no longer be used. */
	readonly isInvalidToken: boolean;
};

/** Result of one Firebase Cloud Messaging delivery handoff. */
export type FirebaseCloudMessagingResult =
	| FirebaseCloudMessagingSuccess
	| FirebaseCloudMessagingFailure;

/** Aggregate result returned after sending Firebase Cloud Messaging messages. */
export type FirebaseCloudMessagingBatchResult = {
	/** Number of messages accepted by Firebase Cloud Messaging. */
	readonly successCount: number;

	/** Number of messages rejected by Firebase Cloud Messaging. */
	readonly failureCount: number;

	/** Ordered result matching every supplied delivery request. */
	readonly results: readonly FirebaseCloudMessagingResult[];
};
