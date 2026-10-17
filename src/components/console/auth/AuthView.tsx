'use client';

import { useRef, useState } from 'react';
import type { KeyboardEvent, SyntheticEvent } from 'react';
import type { AuthViewProps, TerminalEntry } from '@/types/console';
import {
	createAuthenticationProgressMessages, wait, isValidEmailAddress,
	LOGIN_HISTORY_KEY, AUTHENTICATION_PROGRESS_DELAY_MILLISECONDS
} from '@/components/console/auth/terminal';
import '@/components/console/auth/terminal.css';

/**
 * Renders the interactive console authentication screen.
 * @param props - Properties used to render the authentication screen.
 * @returns The console authentication interface.
 */
const AuthView = ({ loginDate }: AuthViewProps) => {
	const commandInputRef = useRef<HTMLInputElement>(null);
	const passwordInputRef = useRef<HTMLInputElement>(null);
	const [user, setUser] = useState({ email: '', password: '' });
	const [command, setCommand] = useState('');
	const [history, setHistory] = useState<TerminalEntry[]>([]);
	const [isAuthenticating, setIsAuthenticating] = useState(false);
	const [isPasswordPromptVisible, setIsPasswordPromptVisible] = useState(false);
	const [passwordAttemptCount, setPasswordAttemptCount] = useState(0);

	const formattedLoginDate = new Intl.DateTimeFormat('en-US', {
		weekday: 'short',
		month: 'short',
		day: '2-digit',
		hour: '2-digit',
		minute: '2-digit',
		second: '2-digit',
		hour12: false,
		timeZone: 'Europe/Paris'
	}).format(new Date(loginDate));

	/**
	 * Adds a terminal line to the current display history.
	 * @param kind - Kind of terminal line to append.
	 * @param content - Text displayed on the line.
	 */
	const appendHistoryEntry = (
		kind: TerminalEntry['kind'],
		content: string
	) => {
		const entry: TerminalEntry = {
			id: crypto.randomUUID(),
			kind,
			content
		};

		setHistory((currentHistory) => [...currentHistory, entry]);
	};

	/**
	 * Displays the decorative authentication progress one line at a time.
	 * @returns A promise resolved when every progress line has been displayed.
	 */
	const displayAuthenticationProgress = async () => {
		const messages = createAuthenticationProgressMessages();

		for (const message of messages) {
			await wait(AUTHENTICATION_PROGRESS_DELAY_MILLISECONDS);
			appendHistoryEntry('output', message);
		}

		await wait(AUTHENTICATION_PROGRESS_DELAY_MILLISECONDS);
		appendHistoryEntry('pending', '🔄 Awaiting identity provider response');
	};

	/**
	 * Interprets and records the command entered in the active prompt.
	 */
	const handleCommand = () => {
		const normalizedCommand = command.trim();

		if (!normalizedCommand) {
			return;
		}

		if (normalizedCommand === 'clear') {
			setHistory([]);
			setCommand('');

			return;
		}

		if (normalizedCommand === 'login') {
			appendHistoryEntry('command', normalizedCommand);
			appendHistoryEntry('output', 'usage: login <email>');
			setCommand('');

			return;
		}

		if (normalizedCommand.startsWith('login ')) {
			const email = normalizedCommand.slice('login '.length).trim();

			if (!isValidEmailAddress(email)) {
				appendHistoryEntry('command', normalizedCommand);
				appendHistoryEntry(
					'output',
					`login: invalid email address: ${ email || '<empty>' }`
				);
				setCommand('');

				return;
			}

			appendHistoryEntry('command', normalizedCommand);

			setUser((currentUser) => ({
				...currentUser,
				email
			}));

			localStorage.setItem(LOGIN_HISTORY_KEY, email);
			setCommand('');
			setPasswordAttemptCount(0);
			setIsPasswordPromptVisible(true);

			return;
		}

		const commandName = normalizedCommand.split(/\s+/)[0];

		const commandEntry: TerminalEntry = {
			id: crypto.randomUUID(),
			kind: 'command',
			content: normalizedCommand
		};

		const errorEntry: TerminalEntry = {
			id: crypto.randomUUID(),
			kind: 'output',
			content: `zsh: command not found: ${ commandName }`
		};

		setHistory((currentHistory) => [
			...currentHistory,
			commandEntry,
			errorEntry
		]);

		setCommand('');
	};

	/**
	 * Navigates the single-entry login history with the arrow keys.
	 * @param event - Keyboard event emitted by the command input.
	 */
	const handleCommandKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
		if (event.key === 'ArrowDown') {
			event.preventDefault();
			setCommand('');

			return;
		}

		if (event.key !== 'ArrowUp') {
			return;
		}

		const savedEmail = localStorage.getItem(LOGIN_HISTORY_KEY);

		if (!savedEmail) {
			return;
		}

		event.preventDefault();
		setCommand(`login ${ savedEmail }`);
	};

	/**
	 * Records a password failure and returns to the command prompt after three attempts.
	 * @param message - Safe error message displayed in the terminal history.
	 */
	const handlePasswordFailure = (message: string) => {
		const nextAttemptCount = passwordAttemptCount + 1;

		appendHistoryEntry('output', `${ user.email }'s password:`);
		appendHistoryEntry('output', message);

		setUser((currentUser) => ({
			...currentUser,
			password: ''
		}));

		if (nextAttemptCount < 3) {
			setPasswordAttemptCount(nextAttemptCount);

			return;
		}

		appendHistoryEntry(
			'output',
			'authentication cancelled: maximum attempts reached'
		);
		setPasswordAttemptCount(0);
		setIsPasswordPromptVisible(false);
	};

	/**
	 * Cancels password entry when the user presses Control+C.
	 * @param event - Keyboard event emitted by the password input.
	 */
	const handlePasswordKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
		if (!event.ctrlKey || event.key.toLowerCase() !== 'c') {
			return;
		}

		event.preventDefault();
		appendHistoryEntry('output', `${ user.email }'s password:`);

		setUser((currentUser) => ({
			...currentUser,
			password: ''
		}));

		setPasswordAttemptCount(0);
		setIsPasswordPromptVisible(false);
	};

	/**
	 * Submits the active terminal prompt.
	 * @param event - Form submission event.
	 */
	const handleSubmit = async (
		event: SyntheticEvent<HTMLFormElement, SubmitEvent>
	) => {
		event.preventDefault();

		if (isPasswordPromptVisible) {
			if (user.password.length === 0) {
				handlePasswordFailure(
					'authentication failed: password is required'
				);

				return;
			}

			appendHistoryEntry('output', `${ user.email }'s password:`);

			setIsPasswordPromptVisible(false);
			setIsAuthenticating(true);

			setUser((currentUser) => ({
				...currentUser,
				password: ''
			}));

			try {
				await displayAuthenticationProgress();
			} catch (error) {
				console.error(error);
			}

			return;
		}

		handleCommand();
	};

	/**
	 * Focuses the input associated with the active authentication step.
	 */
	const handleTerminalClick = () => {
		if (isAuthenticating) {
			return;
		}

		if (isPasswordPromptVisible) {
			passwordInputRef.current?.focus();

			return;
		}

		commandInputRef.current?.focus();
	};

	return (
		<div
			className="bg-[rgb(37,47,74)] dark:bg-[rgb(22,28,44)] text-white/80 min-h-dvh w-full cursor-text overflow-x-hidden select-none font-mono text-xs"
			onClick={ handleTerminalClick }
		>
			<form
				autoComplete="off"
				className="px-4 py-3"
				onSubmit={ handleSubmit }
			>
				<p className="h-4.25 leading-4.25">
					Last login:{ ' ' }
					<time dateTime={ loginDate }>{ formattedLoginDate }</time>
					{ ' on console' }
				</p>

				<div className="mt-2">
					{
						history.map((entry) => {
							if (entry.kind === 'command') {
								return (
									<p key={ entry.id } className="min-h-4.25 break-all leading-4.25">
										<span className="text-green-400">user@assosync</span>
										<span> ~ % </span>
										<span>{ entry.content }</span>
									</p>
								);
							}

							if (entry.kind === 'pending') {
								return (
									<p key={ entry.id } className="min-h-4.25 break-all leading-4.25">
										{ entry.content }
										<span
											aria-hidden="true"
											className="terminal-loading-dots"
										/>
									</p>
								);
							}

							return (
								<p key={ entry.id } className="min-h-4.25 break-all leading-4.25">
									{ entry.content }
								</p>
							);
						})
					}
				</div>

				{
					!isAuthenticating && (
						isPasswordPromptVisible ? (
							<div className="flex min-h-4.25 items-start leading-4.25">
								<label htmlFor="password" className="shrink-0">
									{ user.email }&apos;s password:&nbsp;
								</label>

								<input
									id="password"
									ref={ passwordInputRef }
									name="password"
									type="password"
									autoComplete="current-password"
									autoCapitalize="none"
									autoCorrect="off"
									autoFocus
									spellCheck={ false }
									value={ user.password }
									onChange={ (event) => {
										setUser((currentUser) => ({
											...currentUser,
											password: event.target.value
										}));
									} }
									onKeyDown={ handlePasswordKeyDown }
									className="min-w-0 flex-1 bg-transparent text-transparent caret-transparent outline-none"
								/>
							</div>
						) : (
							<div className="flex min-h-4.25 items-start leading-4.25">
								<label htmlFor="command" className="shrink-0">
									<span className="text-green-400">user@assosync</span>
									<span> ~ %&nbsp;</span>
								</label>

								<div className="relative min-h-4.25 min-w-0 flex-1 leading-4.25">
									<input
										id="command"
										ref={ commandInputRef }
										name="command"
										type="text"
										autoComplete="off"
										autoCapitalize="none"
										autoCorrect="off"
										autoFocus
										spellCheck={ false }
										value={ command }
										onChange={ (event) => {
											setCommand(event.target.value);
										} }
										onKeyDown={ handleCommandKeyDown }
										className="absolute inset-0 h-full min-h-4.25 w-full bg-transparent text-transparent caret-transparent outline-none"
									/>

									<div
										aria-hidden="true"
										className="pointer-events-none min-h-4.25 break-all whitespace-pre-wrap leading-4.25"
									>
										<span>{ command }</span>
										<span className="inline-flex h-4.25 items-center align-top">
									<span className="inline-block h-[1.3em] w-[0.60em] shrink-0 bg-white"/>
								</span>
									</div>
								</div>
							</div>
						)
					)
				}
			</form>
		</div>
	);
};

export default AuthView;
