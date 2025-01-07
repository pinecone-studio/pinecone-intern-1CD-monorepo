import React from 'react';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';

const StoryCard = ({ story, user }: { story: any; user: any }) => {
  return (
    <div
      style={{
        backgroundImage: `url(${story.image || '/images/default-story.jpg'})`,
      }}
      className="h-[435px] w-[245px] flex flex-col items-center justify-center gap-2 bg-no-repeat bg-cover bg-center rounded-md"
    >
      <div className="rounded-full bg-[linear-gradient(to_top_right,#f9ce34_10%,#ee2a7b_60%)] p-[3px]">
        <div className="rounded-full bg-white w-[60px] h-[60px] flex items-center justify-center">
          <Avatar className="w-[56px] h-[56px]">
            <AvatarImage src={user?.profileImg || 'https://github.com/shadcn.png'} alt={user?.userName || 'User'} />
            <AvatarFallback>{user?.userName?.[0]?.toUpperCase() || 'U'}</AvatarFallback>
          </Avatar>
        </div>
      </div>
      <div className="flex flex-col items-center text-white">
        <span>{user?.userName}</span>
        <span className="-mt-1">5h</span>
      </div>
    </div>
  );
};

export default StoryCard;
