import { PropsWithChildren } from 'react';
// import '/../global.css';
import { ApolloWrapper } from '@/components/providers';
import { UserBar } from '@/components/header/UserBar';
import { Header } from '@/components/header/Header';

export const metadata = {
  title: 'Welcome to example-frontend',
  description: 'Generated by create-nx-workspace',
};

const RootLayout = ({ children }: PropsWithChildren) => {
  return (
    <html lang="en">
      <body>
        <ApolloWrapper>
          <div className="relative flex justify-between w-screen">
            <Header />

            <div className="flex h-screen overflow-scroll bg-green-200 ">{children}</div>
            <UserBar />
          </div>
        </ApolloWrapper>
      </body>
    </html>
  );
};

export default RootLayout;