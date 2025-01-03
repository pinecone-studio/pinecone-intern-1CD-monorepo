'use client';

import { Dialog, DialogContent, DialogTitle } from '@/components/ui/dialog';
import Image from 'next/image';
import { Dispatch, SetStateAction, useState } from 'react';
import { CreatePost } from './CreatePost';
import { ArrowLeft } from 'lucide-react';

export const UpdateImagesStep2 = ({
  step,
  setStep,
  images,
  setOpenCreatePostModal,
}: {
  step: boolean;
  setStep: Dispatch<SetStateAction<boolean>>;
  images: string[];
  setOpenCreatePostModal: Dispatch<SetStateAction<boolean>>;
}) => {
  const [openModal, setOpenModal] = useState(false);

  const modal = () => {
    setStep(false);
    setOpenModal(true);
  };
  const closeModal = () => {
    setOpenCreatePostModal(true);
    setStep(false);
  };
  return (
    <Dialog open={step}>
      <DialogContent data-testid="step2" className=" [&>button]:hidden p-0  m-0">
        <DialogTitle className="text-center text-[16px] h-[35px] py-3 ">
          <div className="flex justify-between text-center text-[16px] px-1">
            {' '}
            <button onClick={closeModal} data-testid="Btn1">
              <ArrowLeft width={16} height={16} />
            </button>
            <p>Crop</p>
            <button data-testid="Btn2" className="text-[#2563EB]" onClick={() => modal()}>
              Next
            </button>
          </div>
        </DialogTitle>

        <div className="h-[626px] w-full m-0">
          <div className="relative w-full h-full">
            <Image src={images[0]} alt="img" fill={true} className="object-cover w-auto h-auto rounded-b-lg" />
          </div>
        </div>
      </DialogContent>
      <CreatePost setOpenModal={setOpenModal} openModal={openModal} images={images} setStep={setStep} />
    </Dialog>
  );
};
