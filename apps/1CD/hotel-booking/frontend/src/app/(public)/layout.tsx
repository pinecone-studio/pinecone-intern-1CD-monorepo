import { PropsWithChildren } from 'react';
import '.././global.css';
import FooterHome from '@/components/FooterHome';
import Header from '@/components/Header';
import HotelDetail from '../(client)/hotel-detail/HotelDetail';

const PublicLayout = ({ children }: PropsWithChildren) => {
  return (
    <>
      <Header />
      <HotelDetail />
      {children}
      <FooterHome />
    </>
  );
};

export default PublicLayout;
