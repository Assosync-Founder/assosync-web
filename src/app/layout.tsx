import React from 'react';
import type { ChildrenType } from '@/types/app';
import '@/assets/styles/globals.css';

const RootLayout = async ({ children }: ChildrenType) => {
	return (
		<html lang="fr">
			<body>
				{ children }
			</body>
		</html>
	);
};

export default RootLayout;