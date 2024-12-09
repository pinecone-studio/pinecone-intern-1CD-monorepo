import { PropsWithChildren } from 'react';
import './global.css';
import { ApolloWrapper } from '@/components/providers';
import FooterHome from '@/components/FooterHome';
import Header from '@/components/Header';
import RoomCard from '@/components/RoomCard';

export const metadata = {
  title: 'Welcome to example-frontend',
  description: 'Generated by create-nx-workspace',
};

const RootLayout = ({ children }: PropsWithChildren) => {
  return (
    <html lang="en">
      <body>
        <ApolloWrapper>
          <Header />
          <RoomCard/>
          {children}
          <FooterHome />
        </ApolloWrapper>
      </body>
    </html>
  );
};

export default RootLayout;
