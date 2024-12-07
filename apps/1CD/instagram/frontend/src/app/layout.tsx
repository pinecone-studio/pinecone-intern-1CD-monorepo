'use client';
import { PropsWithChildren } from 'react';
import './global.css';
import { ApolloWrapper } from '@/components/providers';
import { AuthProvider } from '@/components/providers/AuthProvider';
import { Toaster } from '@/components/ui/toaster';

// export const metadata = {
//   title: 'Welcome to example-frontend',
//   description: 'Generated by create-nx-workspace',
// };

const RootLayout = ({ children }: PropsWithChildren) => {
  return (
    <html lang="en">
      <body>
        <ApolloWrapper>
          <AuthProvider>
            {children}
            <Toaster />
          </AuthProvider>
        </ApolloWrapper>
      </body>
    </html>
  );
};

export default RootLayout;
