import 'server-only';

import type { Message, Messaging, SendResponse } from 'firebase-admin/messaging';
import type { FirebaseCloudMessagingBatchResult, FirebaseCloudMessagingMessage, FirebaseCloudMessagingResult } from '@/types/firebase';

const MAX_MESSAGES_PER_BATCH = 500;

const INVALID_TOKEN_ERROR_CODES = new Set([
	'messaging/installation-id-not-registered',
	'messaging/invalid-recipient',
	'messaging/invalid-registration-token',
	'messaging/registration-token-not-registered'
]);

/** Sends push notifications through Firebase Cloud Messaging. */
class FirebaseCloudMessagingService {
	/**
	 * Creates a Firebase Cloud Messaging service.
	 * @param messaging - Initialized Firebase Admin Messaging client.
	 */
	constructor(private readonly messaging: Messaging) {}

	/**
	 * Sends messages while respecting the Firebase batch size limit.
	 * @param messages - Delivery requests containing private registration tokens.
	 * @returns Ordered delivery results without registration tokens.
	 * @throws When Firebase rejects a complete batch request.
	 */
	readonly sendEach = async (messages: readonly FirebaseCloudMessagingMessage[]): Promise<FirebaseCloudMessagingBatchResult> => {
		if (messages.length === 0) {
			return {
				successCount: 0,
				failureCount: 0,
				results: []
			};
		}

		messages.forEach(this.assertMessage);

		const messageChunks = this.chunkMessages(messages);
		const chunkResults = await Promise.all(
			messageChunks.map(async (messageChunk) => {
				const firebaseMessages = messageChunk.map(this.toFirebaseMessage);

				const response = await this.messaging.sendEach(firebaseMessages);

				return response.responses.map((sendResponse, index) => {
					const message = messageChunk[index];

					if (!message) {
						throw new TypeError('The Firebase messaging response is inconsistent.');
					}

					return this.toDeliveryResult(message.recipientId, sendResponse);
				});
			})
		);

		const results = chunkResults.flat();
		const successCount = results.filter((result) => {
			return result.status === 'sent';
		}).length;

		return {
			successCount,
			failureCount: results.length - successCount,
			results
		};
	};

	/**
	 * Converts an internal delivery request into a Firebase message.
	 * @param message - Validated internal delivery request.
	 * @returns The Firebase Admin message payload.
	 */
	private readonly toFirebaseMessage = (message: FirebaseCloudMessagingMessage): Message => {
		return {
			token: message.token.trim(),
			...(message.notification
				? {
					notification: {
						title: message.notification.title,
						body: message.notification.body
					}
				}
				: {}),
			...(message.data
				? { data: { ...message.data } }
				: {})
		};
	};

	/**
	 * Converts one Firebase response into a token-free delivery result.
	 * @param recipientId - Internal recipient identifier.
	 * @param response - Firebase response for the matching message.
	 * @returns The normalized delivery result.
	 */
	private readonly toDeliveryResult = (recipientId: string, response: SendResponse): FirebaseCloudMessagingResult => {
		if (response.success && response.messageId) {
			return {
				recipientId,
				status: 'sent',
				messageId: response.messageId
			};
		}

		const errorCode = response.error?.code ?? null;
		return {
			recipientId,
			status: 'failed',
			errorCode,
			isInvalidToken: errorCode !== null && INVALID_TOKEN_ERROR_CODES.has(errorCode)
		};
	};

	/**
	 * Splits messages into Firebase-compatible batches.
	 * @param messages - Validated delivery requests.
	 * @returns Ordered message batches containing at most 500 entries.
	 */
	private readonly chunkMessages = (messages: readonly FirebaseCloudMessagingMessage[]): readonly (readonly FirebaseCloudMessagingMessage[])[] => {
		const messageChunks: FirebaseCloudMessagingMessage[][] = [];

		for (
			let index = 0;
			index < messages.length;
			index += MAX_MESSAGES_PER_BATCH
		) {
			messageChunks.push(messages.slice(index, index + MAX_MESSAGES_PER_BATCH));
		}

		return messageChunks;
	};

	/**
	 * Validates one Firebase Cloud Messaging delivery request.
	 * @param message - Delivery request to validate.
	 * @throws {TypeError} When the recipient, token, or payload is invalid.
	 */
	private readonly assertMessage = (message: FirebaseCloudMessagingMessage): void => {
		if (!message.recipientId.trim()) {
			throw new TypeError('The Firebase messaging recipient identifier is required.');
		}

		if (!message.token.trim()) {
			throw new TypeError('The Firebase messaging registration token is required.');
		}

		if (message.notification && (!message.notification.title.trim() || !message.notification.body.trim())) {
			throw new TypeError('The Firebase messaging notification is invalid.');
		}

		if (!message.notification && !message.data) {
			throw new TypeError('The Firebase messaging payload is required.');
		}
	};
}

export default FirebaseCloudMessagingService;
