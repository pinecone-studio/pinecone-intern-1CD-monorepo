'use client';
import Image from 'next/image';
import React, { useState } from 'react';

type ChangeProImage = { _id: string; profileImg: string };
type ChangeProfileImg = ({ _id }: ChangeProImage) => void;

const ProImg = ({
  proImgData,
  setProImgData,
  changeProfileImg,
  _id,
  prevProImg,
}: {
  proImgData: string;
  setProImgData: React.Dispatch<React.SetStateAction<string>>;
  changeProfileImg: ChangeProfileImg;
  _id: string | undefined;
  prevProImg: string;
}) => {
  const [image, setImage] = useState<string>(proImgData);

  const handleUploadImg = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = event?.target?.files;
    if (!files || files.length === 0) return;

    const file = files[0];
    const data = new FormData();
    data.append('file', file);
    data.append('upload_preset', 'instagram-intern');
    data.append('cloud_name', 'dka8klbhn');

    const res = await fetch('https://api.cloudinary.com/v1_1/dka8klbhn/image/upload', {
      method: 'POST',
      body: data,
    });
    // if (!res.ok) throw new Error('upload image failed');

    const uploadedImage = await res.json();
    await changeProfileImg({ _id: _id!, profileImg: uploadedImage.secure_url });
    setImage(uploadedImage.secure_url);

    setProImgData(image);
  };
  return (
    <div>
      <label htmlFor="file-upload">
        <div className="relative w-36 h-36 rounded-full">
          <Image sizes="h-auto w-auto" data-testid="proImage" src={prevProImg} alt="profilezurag" fill className="absolute rounded-full object-cover" />
        </div>
      </label>
      <input data-testid="inputImage" id="file-upload" type="file" accept="image/*,video/*" className="hidden" onChange={handleUploadImg} />
    </div>
  );
};
export default ProImg;
