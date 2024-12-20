import { PropsWithChildren } from 'react';
import { ApolloWrapper } from '../../components/providers';

const MainLayout = ({ children }: PropsWithChildren) => {
  return (
    <ApolloWrapper>
      <div className="flex flex-col min-h-screen">
        <div className="flex-1">{children}</div>
      </div>
    </ApolloWrapper>
  );
};

export default MainLayout;
