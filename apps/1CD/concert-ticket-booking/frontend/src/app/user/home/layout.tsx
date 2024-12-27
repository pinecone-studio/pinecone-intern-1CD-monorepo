import { PropsWithChildren } from 'react';

import { Footer } from '@/components/footer/Footer';
import { Header } from '@/components/header/Header';

export const metadata = {
  title: 'Welcome to example-frontend',
  description: 'Generated by create-nx-workspace',
};
const UserLayout = ({ children }: PropsWithChildren) => {
  return (
    <div className="bg-black ">
      <div className="max-w-[1334px] m-auto bg-zinc-950 ">
        <Header />
        <div>{children}</div>
        <Footer />
      </div>
    </div>
  );
};
export default UserLayout;
