'use client';

import { usePaymentTicketsMutation } from '@/generated';
import { Check, CircleX } from 'lucide-react';
import Link from 'next/link';
import { useEffect, useState } from 'react';

import { toast } from 'sonner';

const QRGeneratePage = ({ params }: { params: { id: string } }) => {
  const [check, setScheck] = useState(false);
  const [paymentTicket] = usePaymentTicketsMutation({
    onCompleted: () => {
      setScheck(true);
      toast.success('Thank you for your purchase, please check your email');
    },
    onError: (error: any) => {
      toast.error(error.message);
    },
  });
  const makePayment = async () => {
    await paymentTicket({
      variables: {
        orderId: params.id,
      },
    });
  };
  useEffect(() => {
    makePayment();
  }, []);
  return (
    <div>
      <div>
        {check ? (
          <div data-cy="payment-sucsess-title" className="flex flex-col items-center justify-center w-full h-screen gap-6 text-white">
            <div className="w-24 h-24 flex flex-col justify-center bg-[#131313] rounded-full items-center">
              <Check className="w-10 h-9 text-[#00B7F4]" />
            </div>
            <div className="text-lg font-normal leading-9 text-white">Захиалга амжилттай баталгаажлаа</div>
            <div className="text-base font-light leading-4 text-center text-zinc-600">
              Таны имэйл хаяг руу цахим тасалбар <br /> амжилттай илгээгдлээ
            </div>
            <Link href="/user/home">
              <button className="font-medium leading-5 text-white m-4 p-2  text-[12px] rounded-md bg-[#00B7f4] w-34">Үндсэн хуудас руу буцах </button>
            </Link>
          </div>
        ) : (
          <div data-cy="payment-error-title" className="flex flex-col items-center justify-center w-full h-screen gap-6 text-white">
            <CircleX className="w-24 h-24 text-red-500" />
            <p className="text-lg font-normal leading-9 text-white">Хүсэлт ажилтгүй боллоо</p>
            <Link href="/user/home">
              <button className="font-medium leading-5 text-white m-4 p-2  text-[12px] rounded-md bg-[#00B7f4] w-34">Үндсэн хуудас руу буцах </button>
            </Link>
          </div>
        )}
      </div>
    </div>
  );
};
export default QRGeneratePage;
