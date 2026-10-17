/**
 * Represents a line already written in the authentication terminal.
 */
export type TerminalEntry = {
	/**
	 * Unique identifier used when rendering the entry.
	 */
	id: string;

	/**
	 * Determines whether the line is a command or terminal output.
	 */
	kind: 'command' | 'output' | 'pending';

	/**
	 * Text displayed on the terminal line.
	 */
	content: string;
};

/**
 * Properties accepted by the console authentication view.
 */
export type AuthViewProps = {
	/**
	 * ISO-formatted date displayed as the last login date.
	 */
	loginDate: string;
};
