'use client';
import { PropsWithChildren, Suspense } from 'react';
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
        <Suspense>
          <ApolloWrapper>
            <AuthProvider>
              {children}
              <Toaster />
            </AuthProvider>
          </ApolloWrapper>
        </Suspense>
      </body>
    </html>
  );
};

export default RootLayout;
