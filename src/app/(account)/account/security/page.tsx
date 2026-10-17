import PasskeyManagementView from '@/core/auth/views/PasskeyManagementView';

/** Renders the account security settings. */
const AccountSecurityPage = () => {
	return (
		<main>
			<h1>Sécurité du compte</h1>
			<PasskeyManagementView />
		</main>
	);
};

export default AccountSecurityPage;
