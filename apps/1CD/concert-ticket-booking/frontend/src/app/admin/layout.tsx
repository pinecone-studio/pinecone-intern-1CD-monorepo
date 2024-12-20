import { PropsWithChildren } from 'react';
import { AdminHeader } from './home/_components/adminHeader';
import { AdminFooter } from './home/_components/AdminFooter';

export const metadata = {
  title: 'Welcome to example-frontend',
  description: 'Generated by create-nx-workspace',
};

const Layout = ({ children }: PropsWithChildren) => {
  return (
    <html lang="en">
      <body>
        <AdminHeader/>
        <div>{children}</div>
        <AdminFooter/>
      </body>
    </html>
  );
};

export default Layout;
