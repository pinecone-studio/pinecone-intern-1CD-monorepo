'use clien';

import { useRouter } from 'next/navigation';
import { useAuth } from './AuthProvider';
import { ReactNode } from 'react';

const CheckLoginUser = ({ children }: { children: ReactNode }) => {
  const router = useRouter();
  const { user } = useAuth();
  if (!user) {
    router.push('/login');
    return null;
  }
  return <div>{children}</div>;
};

export default CheckLoginUser;
