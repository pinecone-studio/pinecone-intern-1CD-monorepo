import { Hotel } from '@/generated';
import { Wifi } from 'lucide-react';
import { Flower } from 'lucide-react';
import { CircleParking } from 'lucide-react';
import { Star } from 'lucide-react';
import Image from 'next/image';

const HomePageCard = ({ hotel }: { hotel: Hotel }) => {
  return (
    <div>
      <div className="max-w-[380px] w-full h-auto border-2 rounded-md">
        <div>{hotel.hotelName}</div>

        <div className="w-full h-[216px] bg-pink-100">
          <Image className="object-cover w-full h-full" src={'/'} alt="image" height={1000} width={1000} />
        </div>
        <div className="p-4">
          <div className="pb-3">
            <p className="font-bold">Economy Double Room, City View</p>
            <div className="flex gap-1">
              <Star className="w-[16px] text-[#F97316] fill-[#F97316]" />
              <Star className="w-[16px] text-[#F97316] fill-[#F97316]" />
              <Star className="w-[16px] text-[#F97316] fill-[#F97316]" />
            </div>
          </div>
          <div className="flex gap-1.5 items-center pb-3">
            <Wifi className="w-[16px]" />
            <p className="text-[14px]">Free WIFI</p>
          </div>
          <div className="flex gap-1.5 items-center pb-3">
            <Flower className="w-[16px]" />
            <p className="text-[14px]">Spa access</p>
          </div>
          <div className="flex gap-1.5 items-center pb-3">
            <CircleParking className="w-[16px]" />
            <p className="text-[14px]">Free self parking</p>
          </div>
          <div className="flex gap-1.5 items-center pb-3">
            <div className="bg-[#18BA51] text-white py-0.5 px-2.5 rounded-full text-[12px] font-semibold">8.6</div>
            <p className="text-[14px]">Excellent</p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default HomePageCard;
