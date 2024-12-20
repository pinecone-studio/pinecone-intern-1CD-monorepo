import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { RoomType } from '@/generated';

import { X } from 'lucide-react';
import Link from 'next/link';
const PriceDetail = ({ room, handleOpen, isOn }: { room: RoomType; isOn: boolean; handleOpen: () => void }) => {
  return (
    <Dialog open={isOn}>
      <DialogContent className="p-6 max-w-screen-sm">
        <DialogHeader>
          <DialogTitle className="flex justify-between">
            <div className="text-xl font-semibold">Price Detail</div>
            <button className="outline-none" onClick={handleOpen}>
              <X className="w-4 h-4" />
            </button>
          </DialogTitle>
        </DialogHeader>

          <div className="flex justify-between items-center">
            <div>
              <p className="text-sm font-normal">2 night</p>
              <p className="text-sm font-normal text-muted-foreground">₮{room?.price} per night</p>
            </div>
            <div className="text-sm font-medium">₮ 150,000</div>
          </div>
          <div className="w-full border border-solid 1px bg-[#E4E4E7]"></div>
          <div className="flex justify-between">
            <div className="text-sm font-medium">Total price</div>
            <div className="text-lg font-semibold">₮ 300,000</div>
          </div>

        <div className='w-full items-center'>
          <Link href={`/checkout/${room._id}`} className="bg-[#2563EB] rounded-md py-2 px-3 text-white">Reserve</Link>
        </div>
      </DialogContent>
    </Dialog>
  );
};
export default PriceDetail;
