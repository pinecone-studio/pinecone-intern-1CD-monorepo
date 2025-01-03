'use client';
import { useGetCommentsQuery } from '@/generated';
import React from 'react';
import { Dialog, DialogContent, DialogTrigger } from '@/components/ui/dialog';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';
import Image from 'next/image';
import { Button } from '@/components/ui/button';
import { Bookmark, Heart, MessageCircle, MoreVertical, SmileIcon } from 'lucide-react';
import { CommentCard } from '../../../components/comment/CommentCard';

export const PostWithComments = ({ id }: { id: string }) => {
  const { data: commentsData } = useGetCommentsQuery({
    variables: {
      postId: id,
    },
  });

  return (
    <Dialog data-testid="postWithComments1">
      <DialogTrigger data-testid="open-comment-btn" asChild>
        <div className="flex flex-row py-1 space-x-2 text-sm text-gray-500 hover:cursor-pointer">
          <p className="cursor-pointer">
            {commentsData?.getComments?.length === 0 ? '' : `${commentsData?.getComments?.length === 1 ? `View comment` : `View all ${commentsData?.getComments?.length} comments`}`}
          </p>
        </div>
      </DialogTrigger>
      <DialogContent className="[&>button]:hidden p-0 m-0 ">
        <div className="bg-white rounded-lg w-[1256px] h-[800px] [&>button]:hidden p-0 flex  " data-testid="postWithComments">
          <div className="w-full ">
            <div className="relative w-[800px] h-full">
              <Image src={'/images/profileImg.webp'} alt="img" fill={true} className="object-cover w-auto h-auto rounded-tl-lg rounded-bl-lg" />
            </div>
          </div>
          <div className="flex flex-col justify-between w-full px-3 py-4 ">
            <div className="flex flex-col w-full">
              <div className="flex items-center justify-between border-b-[1px] pb-3 mb-4">
                <div className="flex items-center gap-4">
                  <div className="relative flex w-8 h-8 rounded-full">
                    <Image fill={true} src={'/images/profileImg.webp'} alt="Photo1" className="w-auto h-auto rounded-full" />
                  </div>
                  <h1 className="text-sm font-bold ">userName</h1>
                </div>
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button variant="ghost" className="w-4 h-4 p-0 ">
                      <MoreVertical />
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent>
                    <DropdownMenuItem className="text-red-600">Delete</DropdownMenuItem>
                    <DropdownMenuItem>Edit</DropdownMenuItem>
                    <DropdownMenuItem>Cancel</DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>
              </div>

              <div className="flex items-center w-full gap-4 py-1">
                <div className="">
                  <div className="relative w-8 h-8 rounded-full">
                    <Image src={'/images/profileImg.webp'} alt="proZurag" fill className="absolute object-cover rounded-full" sizes="w-auto h-auto" />
                  </div>
                </div>
                <div className="flex flex-col gap-1 text-sm font-normal text-black">
                  <h1 className="text-sm font-bold text-black ">
                    userName
                    <span className="pl-1 font-normal text-wrap">We should catch up soon ! L</span>
                  </h1>
                  <p className="text-[12px] text-[#71717A]">1w</p>
                </div>
              </div>

              <CommentCard id={id} />
            </div>
            <div className="flex flex-col ">
              <div className="border-y-[1px] pb-4 mb-4">
                <div className="flex items-center justify-between px-1 py-3 text-xl">
                  <div className="flex gap-3">
                    <Heart />
                    <p>
                      <MessageCircle />
                    </p>
                  </div>
                  <p>
                    <Bookmark />
                  </p>
                </div>
                <p className="text-sm ">21234 Likes</p>
                <p className="text-[12px] text-[#71717A]">1 day ago</p>
              </div>
              <div className="flex gap-4">
                <SmileIcon width={20} height={20} />
                <input type="text" placeholder="Add a comment ..." />
              </div>
            </div>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
};
