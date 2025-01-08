import { Button } from '@/components/ui/button';
import Image from 'next/image';
const NotifyFollowRequestCard = () => {
  return (
    <div className="flex items-center justify-between gap-4 px-3 py-2">
      <div className="flex items-center gap-3">
        <div className="relative flex rounded-full w-[44px] h-[44px]">
          <Image fill={true} src="/images/img.avif" alt="Photo1" className="h-full rounded-full w-fit" />
        </div>
        <div className="flex flex-col text-[#09090B] max-w-28">
          <span className="text-sm ">username</span>
          <div className="text-xs">
            <span className="mr-1">has requested to follow you</span>
            <span className="text-[#71717A]">10m</span>
          </div>
        </div>
      </div>
      <div className="flex gap-2">
        <Button className="bg-[#2563EB] rounded-lg text-[#FAFAFA]" data-testid="confirm-btn">
          Confirm
        </Button>
        <Button className="bg-[#F4F4F5] rounded-lg text-[#18181B]" data-testid="delete-btn">
          Delete
        </Button>
      </div>
    </div>
  );
};
export default NotifyFollowRequestCard;
