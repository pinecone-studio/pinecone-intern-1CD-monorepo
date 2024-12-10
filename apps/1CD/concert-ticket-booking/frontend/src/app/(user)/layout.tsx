import { PropsWithChildren } from 'react';
import { ApolloWrapper, AuthProvider } from '@/components/providers';
import { Toaster } from '@/components/ui/sonner';

import { Footer } from '@/components/footer/Footer';
import { Header } from './Header';

export const metadata = {
  title: 'Welcome to example-frontend',
  description: 'Generated by create-nx-workspace',
};

const UserLayout = ({ children }: PropsWithChildren) => {
  return (
    <html lang="en">
      <body>
        <ApolloWrapper>
          <AuthProvider>
            <Header />
            <div>{children}</div>
            <Footer />
            <Toaster />
          </AuthProvider>
        </ApolloWrapper>
      </body>
    </html>
  );
};

export default UserLayout;