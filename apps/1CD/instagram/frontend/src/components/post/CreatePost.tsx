'use client';

import { Dialog, DialogContent, DialogTitle } from '@/components/ui/dialog';
import Image from 'next/image';
import { Dispatch, SetStateAction, useState } from 'react';
import { useCreatePostMutation, useGetUserQuery } from '@/generated';
import { ArrowLeft, SmileIcon } from 'lucide-react';

export const CreatePost = ({
  openModal,
  setOpenModal,
  images,
  setStep,
}: {
  images: string[];
  openModal: boolean;
  setOpenModal: Dispatch<SetStateAction<boolean>>;
  setStep: Dispatch<SetStateAction<boolean>>;
}) => {
  const [handleDesc, setHandleDesc] = useState('');

  const [createPost] = useCreatePostMutation();
  const { data: user } = useGetUserQuery();

  const handleCreatePost = async () => {
    await createPost({
      variables: {
        images: images,
        description: handleDesc,
      },
    });
  };
  const createPostBtn = () => {
    handleCreatePost();
    setOpenModal(false);
  };
  const closeModal = () => {
    setOpenModal(false);
    setStep(true);
  };
  return (
    <Dialog open={openModal}>
      <DialogContent className="[&>button]:hidden p-0 m-0 ">
        <div className="bg-white rounded-lg w-[997px] h-[679px] [&>button]:hidden p-0 flex flex-col gap-4  ">
          <div>
            <DialogTitle className="text-center text-[16px] h-[35px] py-3  ">
              <div className="flex justify-between text-center text-[16px] px-1">
                {' '}
                <button data-testid="closeModalBtn" onClick={closeModal}>
                  <ArrowLeft width={16} height={16} />
                </button>
                <p>Create new post</p>
                <button data-testid="createBtn" className="text-[#2563EB]" onClick={() => createPostBtn()}>
                  Share
                </button>
              </div>
            </DialogTitle>
          </div>

          <div className="flex w-full h-full m-0">
            <div className="relative w-[654px] h-[628px]">
              <Image src={images[0]} alt="img" fill={true} className="object-cover w-auto h-auto rounded-bl-lg" />
            </div>
            <div className="w-[343px] p-4 gap-2 flex flex-col border-t-[1px] ">
              <div className="flex items-center gap-2">
                <div className="relative flex w-8 h-8 rounded-full">
                  <Image fill={true} src={user?.getUser.profileImg || '/images/profileImg.webp'} alt="Photo1" className="w-auto h-auto rounded-full" />
                </div>
                <h1 className="text-sm font-bold ">{user?.getUser.userName}</h1>
              </div>
              <input data-testid="input" type="text" className="w-full h-[132px] border rounded-lg p-2" placeholder="Description ..." onChange={(e) => setHandleDesc(e.target.value)} />
              <div className="flex justify-between border-b-[1px] py-3 text-[12px] text-[#71717A] ">
                <SmileIcon width={20} height={20} />
                <p>{handleDesc.length}/200</p>
              </div>
            </div>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
};
