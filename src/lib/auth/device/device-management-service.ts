import 'server-only';

import DeviceService from '@/lib/auth/device/device-service';
import SessionService from '@/lib/auth/session/session-service';
import type { AccountDevice, Device, RevokeManagedDeviceResult } from '@/types/auth';

/** Coordinates account device management with session revocation. */
class DeviceManagementService {
	/**
	 * Creates an account device management service.
	 * @param devices - Trusted device service.
	 * @param sessions - Application session service.
	 */
	constructor(private readonly devices: DeviceService, private readonly sessions: SessionService) {}

	/**
	 * Lists devices without exposing their stored token hashes.
	 * @param userId - Firebase user owning the devices.
	 * @param currentDeviceId - Device associated with the current session.
	 * @returns Public account devices.
	 */
	readonly list = async (userId: string, currentDeviceId: string): Promise<readonly AccountDevice[]> => {
		const devices = await this.devices.list(userId);

		return devices.map((device) => {
			return this.toAccountDevice(device, currentDeviceId);
		});
	};

	/**
	 * Renames a device without exposing its stored token hash.
	 * @param userId - Firebase user owning the device.
	 * @param deviceId - Device identifier.
	 * @param displayName - New optional device label.
	 * @param currentDeviceId - Device associated with the current session.
	 * @returns The renamed public device.
	 */
	readonly rename = async (userId: string, deviceId: string, displayName: string | null, currentDeviceId: string): Promise<AccountDevice> => {
		const device = await this.devices.rename(userId, deviceId, displayName);

		return this.toAccountDevice(device, currentDeviceId);
	};

	/**
	 * Revokes a device and all application sessions associated with it.
	 * @param userId - Firebase user owning the device.
	 * @param deviceId - Device identifier.
	 * @param currentDeviceId - Device associated with the current session.
	 * @returns The revoked public device and revoked session count.
	 */
	readonly revoke = async (userId: string, deviceId: string, currentDeviceId: string): Promise<RevokeManagedDeviceResult> => {
		const device = await this.devices.revoke(userId, deviceId);

		const revokedSessionCount = await this.sessions.revokeByDevice(userId, deviceId);

		return {
			device: this.toAccountDevice(device, currentDeviceId),
			revokedSessionCount
		};
	};

	/**
	 * Removes private fields from a device returned to account consumers.
	 * @param device - Internal device record.
	 * @param currentDeviceId - Device associated with the current session.
	 * @returns The public account device.
	 */
	private readonly toAccountDevice = (device: Device, currentDeviceId: string): AccountDevice => {
		return {
			id: device.id,
			userId: device.userId,
			applicationId: device.applicationId,
			displayName: device.displayName,
			category: device.category,
			browserName: device.browserName,
			browserVersion: device.browserVersion,
			operatingSystemName: device.operatingSystemName,
			operatingSystemVersion: device.operatingSystemVersion,
			deviceBrand: device.deviceBrand,
			deviceModel: device.deviceModel,
			status: device.status,
			createdAt: device.createdAt,
			expiresAt: device.expiresAt,
			lastSeenAt: device.lastSeenAt,
			verifiedAt: device.verifiedAt,
			revokedAt: device.revokedAt,
			isCurrent: device.id === currentDeviceId
		};
	};
}

export default DeviceManagementService;
