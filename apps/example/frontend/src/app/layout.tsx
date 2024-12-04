import { PropsWithChildren } from 'react';
import './global.css';
import 'react-toastify/dist/ReactToastify.css';
export const metadata = {
  title: 'Welcome to example-frontend',
  description: 'Generated by create-nx-workspace',
};

const RootLayout = ({ children }: PropsWithChildren) => {
  console.log();
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
};

export default RootLayout;
