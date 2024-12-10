import { PropsWithChildren } from 'react';
import '../global.css';

import { Header } from '@/components/header/Header';
import { ApolloWrapper } from '@/components/providers';

// export const metadata = {
//   title: 'Welcome to example-frontend',
//   description: 'Generated by create-nx-workspace',
// };

const RootLayout = ({ children }: PropsWithChildren) => {
  return (
    <html lang="en">
      <body>
        <ApolloWrapper>
          <div className="relative flex justify-between w-screen gap-10 pr-1">
            <Header />
            <div className="flex w-full h-screen overflow-scroll">{children}</div>
          </div>
        </ApolloWrapper>
      </body>
    </html>
  );
};

export default RootLayout;
