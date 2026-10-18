export const LOGIN_HISTORY_KEY = 'assosync.console.login-email';
export const AUTHENTICATION_PROGRESS_DELAY_MILLISECONDS = 25;
const AUTHENTICATION_PACKAGES = [
	{
		source: 'auth://sessions.assosync.internal console/main amd64 Session-Index',
		sizeKilobytes: 42.8
	},
	{
		source: 'auth://permissions.assosync.internal console-security InRelease',
		sizeKilobytes: 18.4
	},
	{
		source: 'auth://directory.assosync.internal employees/main Identity-Sources',
		sizeKilobytes: 126
	},
	{
		source: 'auth://policies.assosync.internal stable/main Access-Rules',
		sizeKilobytes: 84.2
	},
	{
		source: 'auth://workspaces.assosync.internal console/main Workspace-Manifest',
		sizeKilobytes: 36.7
	},
	{
		source: 'auth://tokens.assosync.internal secure/main Session-Parameters',
		sizeKilobytes: 12.1
	},
	{
		source: 'auth://audit.assosync.internal events/main Authentication-Schema',
		sizeKilobytes: 28.6
	},
	{
		source: 'auth://roles.assosync.internal employees/main Role-Mappings',
		sizeKilobytes: 53.9
	},
	{
		source: 'auth://console.assosync.internal stable/main Runtime-Profile',
		sizeKilobytes: 17.3
	}
];

/**
 * Generates a random integer within an inclusive range.
 * @param minimum - Smallest possible value.
 * @param maximum - Largest possible value.
 * @returns A random integer between the supplied boundaries.
 */
const getRandomInteger = (minimum: number, maximum: number) => {
	return Math.floor(Math.random() * (maximum - minimum + 1)) + minimum;
};

/**
 * Checks whether a command argument has a valid email address structure.
 * @param value - Email address candidate.
 * @returns Whether the value can be used as a login email.
 */
export const isValidEmailAddress = (value: string) => {
	return /^[^\s@]+@[^\s@.]+(?:\.[^\s@.]+)*\.[^\s@.]{2,}$/.test(value);
};

/**
 * Creates the decorative output displayed during authentication.
 * @returns Terminal-like authentication progress messages.
 */
export const createAuthenticationProgressMessages = () => {
	const receivedKilobytes = AUTHENTICATION_PACKAGES.reduce(
		(totalKilobytes, packageEntry) => {
			return totalKilobytes + packageEntry.sizeKilobytes;
		},
		0
	);
	const durationSeconds = getRandomInteger(1, 3);
	const transferRate = Math.round(receivedKilobytes / durationSeconds);
	const formattedReceivedKilobytes = receivedKilobytes.toLocaleString('en-US', { minimumFractionDigits: 1, maximumFractionDigits: 1 });
	const formattedTransferRate = transferRate.toLocaleString('en-US');
	const packageMessages = AUTHENTICATION_PACKAGES.map((packageEntry, index) => {
		const packageNumber = index + 2;
		const formattedSize = packageEntry.sizeKilobytes.toLocaleString('en-US');

		return `Get:${ packageNumber } ${ packageEntry.source } [${ formattedSize } kB]`;
	});

	return [
		'Hit:1 auth://identity.assosync.internal stable InRelease',
		...packageMessages,
		`${ formattedReceivedKilobytes } kB received in ${ durationSeconds }s (${ formattedTransferRate } kB/s)`,
		'Reading identity manifests… Done',
		'Building authorization context… Done',
		'Reading workspace permissions… Done',
		'Validating session parameters… Done',
		'Authentication request submitted'
	];
};

/**
 * Waits before displaying the next authentication operation.
 * @param durationMilliseconds - Delay duration in milliseconds.
 * @returns A promise resolved after the requested delay.
 */
export const wait = (durationMilliseconds: number) => {
	return new Promise<void>((resolve) => {
		setTimeout(resolve, durationMilliseconds);
	});
};