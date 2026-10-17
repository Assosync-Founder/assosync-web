import React from 'react';
import AuthView from '@/components/console/auth/AuthView';

const ConsoleLoginPage = () => {
	const loginDate = new Date();

	return <AuthView loginDate={loginDate.toISOString()}/>;
};

export default ConsoleLoginPage;