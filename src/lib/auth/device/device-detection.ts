import 'server-only';

import Bowser from 'bowser';
import type { DetectedDeviceInformation } from '@/types/auth';

const MAXIMUM_INFORMATION_LENGTH = 80;

/**
 * Normalizes a bounded value obtained from an HTTP header or Bowser.
 * @param value - Untrusted device information.
 * @returns A safe display value or null.
 */
const normalizeInformation = (
	value: string | null | undefined
): string | null => {
	if (!value) {
		return null;
	}

	const normalizedValue = value
		.trim()
		.replace(/^"|"$/gu, '')
		.replace(/[\u0000-\u001F\u007F]/gu, '');

	if (!normalizedValue) {
		return null;
	}

	return normalizedValue.slice(0, MAXIMUM_INFORMATION_LENGTH);
};

/**
 * Extracts browser brands from the structured Client Hints header.
 * @param value - Raw Sec-CH-UA header value.
 * @returns Browser brands accepted by Bowser.
 */
const parseClientBrands = (
	value: string | null
) => {
	if (!value) {
		return [];
	}

	return [...value.matchAll(/"([^"]+)";v="([^"]+)"/gu)]
		.map((match) => {
			const brand = normalizeInformation(match[1]);
			const version = normalizeInformation(match[2]);

			if (!brand || !version) {
				return null;
			}

			return { brand, version };
		})
		.filter((brand) => brand !== null);
};

/**
 * Derives non-sensitive device information from standard request headers.
 * @param headers - Incoming browser request headers.
 * @returns Best-effort device information suitable for user-facing security UI.
 */
const detectDeviceInformation = (
	headers: Headers
): DetectedDeviceInformation => {
	const userAgent = headers.get('user-agent')?.slice(0, 512) ?? '';
	const mobileHint = headers.get('sec-ch-ua-mobile');
	const platformHint = normalizeInformation(
		headers.get('sec-ch-ua-platform')
	);

	const platformVersionHint = normalizeInformation(
		headers.get('sec-ch-ua-platform-version')
	);

	const deviceModelHint = normalizeInformation(
		headers.get('sec-ch-ua-model')
	);

	const clientHints = {
		brands: parseClientBrands(headers.get('sec-ch-ua')),
		mobile: mobileHint === '?1',
		platform: platformHint ?? undefined,
		platformVersion: platformVersionHint ?? undefined,
		model: deviceModelHint ?? undefined
	};

	const detected = userAgent
		? Bowser.parse(userAgent, clientHints)
		: null;

	const browserName = normalizeInformation(detected?.browser.name);
	const browserVersion = normalizeInformation(detected?.browser.version);
	const operatingSystemName = (
		platformHint && platformHint !== 'Unknown'
			? platformHint
			: normalizeInformation(detected?.os.name)
	);

	const operatingSystemVersion = (
		platformHint && platformHint !== 'Unknown'
			? platformVersionHint
			: normalizeInformation(detected?.os.version)
	);

	const detectedCategory = detected?.platform.type;
	const isTablet = detectedCategory === 'tablet';
	const isMobile = (
		mobileHint === '?1' ||
		detectedCategory === 'mobile'
	);

	let category: DetectedDeviceInformation['category'] = 'unknown';

	if (isTablet) {
		category = 'tablet';
	} else if (isMobile) {
		category = 'mobile';
	} else if (userAgent || operatingSystemName) {
		category = 'desktop';
	}

	const deviceModel = (
		deviceModelHint ??
		normalizeInformation(detected?.platform.model)
	);

	const isAppleDevice = (
		detected?.platform.vendor === 'Apple' ||
		operatingSystemName === 'iOS' ||
		operatingSystemName === 'macOS'
	);

	const detectedDeviceBrand = normalizeInformation(
		detected?.platform.vendor
	);

	return {
		category,
		browserName,
		browserVersion,
		operatingSystemName,
		operatingSystemVersion,
		deviceBrand: isAppleDevice ? 'Apple' : detectedDeviceBrand,
		deviceModel
	};
};

export default detectDeviceInformation;
