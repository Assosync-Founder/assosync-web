import type {
	AuthenticationResponseJSON,
	AuthenticatorTransport,
	RegistrationResponseJSON
} from '@simplewebauthn/server';
import { AuthHttpError } from '@/lib/auth/http/auth-http';

const isRecord = (value: unknown): value is Record<string, unknown> => {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
};

const readString = (record: Record<string, unknown>, key: string): string => {
	const value = record[key];

	if (typeof value !== 'string' || !value || value.length > 16_384) {
		throw new AuthHttpError(400, 'request_invalid');
	}

	return value;
};

const readAttachment = (
	record: Record<string, unknown>
): 'platform' | 'cross-platform' | undefined => {
	const value = record.authenticatorAttachment;

	if (value === undefined) {
		return undefined;
	}

	if (value !== 'platform' && value !== 'cross-platform') {
		throw new AuthHttpError(400, 'request_invalid');
	}

	return value;
};

const readTransports = (
	record: Record<string, unknown>
): AuthenticatorTransport[] | undefined => {
	const value = record.transports;

	if (value === undefined) {
		return undefined;
	}

	if (
		!Array.isArray(value) ||
		!value.every((transport) => {
			return (
				transport === 'ble' ||
				transport === 'hybrid' ||
				transport === 'internal' ||
				transport === 'nfc' ||
				transport === 'usb'
			);
		})
	) {
		throw new AuthHttpError(400, 'request_invalid');
	}

	return value;
};

/** Parses a WebAuthn registration response at the HTTP boundary.
 * @param value - Untrusted JSON value.
 * @returns Validated registration response.
 */
const readRegistrationResponse = (
	value: unknown
): RegistrationResponseJSON => {
	if (!isRecord(value) || !isRecord(value.response)) {
		throw new AuthHttpError(400, 'request_invalid');
	}

	const attachment = readAttachment(value);
	const transports = readTransports(value.response);

	return {
		id: readString(value, 'id'),
		rawId: readString(value, 'rawId'),
		type: 'public-key',
		clientExtensionResults: {},
		response: {
			clientDataJSON: readString(value.response, 'clientDataJSON'),
			attestationObject: readString(value.response, 'attestationObject'),
			...(transports ? { transports } : {})
		},
		...(attachment ? { authenticatorAttachment: attachment } : {})
	};
};

/** Parses a WebAuthn authentication response at the HTTP boundary.
 * @param value - Untrusted JSON value.
 * @returns Validated authentication response.
 */
const readAuthenticationResponse = (
	value: unknown
): AuthenticationResponseJSON => {
	if (!isRecord(value) || !isRecord(value.response)) {
		throw new AuthHttpError(400, 'request_invalid');
	}

	const attachment = readAttachment(value);
	const userHandle = value.response.userHandle;

	if (userHandle !== undefined && typeof userHandle !== 'string') {
		throw new AuthHttpError(400, 'request_invalid');
	}

	return {
		id: readString(value, 'id'),
		rawId: readString(value, 'rawId'),
		type: 'public-key',
		clientExtensionResults: {},
		response: {
			clientDataJSON: readString(value.response, 'clientDataJSON'),
			authenticatorData: readString(value.response, 'authenticatorData'),
			signature: readString(value.response, 'signature'),
			...(userHandle ? { userHandle } : {})
		},
		...(attachment ? { authenticatorAttachment: attachment } : {})
	};
};

export { readAuthenticationResponse, readRegistrationResponse };
