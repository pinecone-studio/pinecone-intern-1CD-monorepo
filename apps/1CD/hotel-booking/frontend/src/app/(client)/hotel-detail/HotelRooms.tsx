'use client';

import { useHotelDetailQuery } from '@/generated';
import { Button } from '@/components/ui/button';
import RoomCard from '@/components/RoomCard';
const HotelRooms = () => {
  const { data } = useHotelDetailQuery({ variables: { hotelId: '674bfbd6a111c70660b55541' } });
  return (
    <div data-cy="Hotel-Rooms" className="flex flex-col gap-4">
      <div className="text-2xl font-semibold">Choose your room</div>
      <div className="bg-[#F4F4F5] rounded-lg max-w-56 flex justify-between p-1">
        <Button variant={'ghost'} className={`px-3 py-1 text-sm font-medium rounded-sm text-[#71717A] hover:bg-white`}>
          All Rooms
        </Button>
        <Button variant={'ghost'} className={`px-3 py-1 text-sm font-medium rounded-sm text-[#71717A] hover:bg-white`}>
          1 bed
        </Button>
        <Button variant={'ghost'} className={`px-3 py-1 text-sm font-medium rounded-sm text-[#71717A] hover:bg-white`}>
          2 bed
        </Button>
      </div>
      <div data-cy="Room-Card" className="grid grid-cols-3 gap-4">
        {data?.hotelDetail.map((room) => (
          <div key={room._id}>
            <RoomCard room={room} />
          </div>
        ))}
      </div>
    </div>
  );
};
export default HotelRooms;
