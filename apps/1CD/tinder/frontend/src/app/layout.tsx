import { PropsWithChildren } from 'react';
import './global.css';
import { ApolloWrapper } from '@/components/providers';
import { Toaster } from '@/components/ui/sonner';

export const metadata = {
  title: 'Welcome to example-frontend',
  description: 'Generated by create-nx-workspace',
};

const RootLayout = ({ children }: PropsWithChildren) => {
  return (
    <html lang="en">
      <body className="">
        <ApolloWrapper>
          <div className="max-w-[1280px] mx-auto">
            {children}
            <Toaster />
          </div>
        </ApolloWrapper>
      </body>
    </html>
  );
};

export default RootLayout;
