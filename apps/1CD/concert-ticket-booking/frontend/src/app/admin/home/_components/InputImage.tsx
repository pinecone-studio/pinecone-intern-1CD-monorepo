'use client';
import React, { useRef, useState } from 'react';
import { UseFormReturn } from 'react-hook-form';
import { FormControl, FormField, FormItem, FormLabel } from '@/components/ui/form';
import { EventInputType } from '@/utils/validation-schema';
import { Loader, X } from 'lucide-react';
import { Input } from '@/components/ui/input';
import axios from 'axios';
type FormProps = {
  form: UseFormReturn<EventInputType>;
};
const InputImage = ({ form }: FormProps) => {
  const [image, setImage] = useState('');
  const [uploading, setUploading] = useState(false);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const handleImageUpload = async (file: File) => {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('upload_preset', 'concertpreset');
    setUploading(true);
    const response = await axios.post(`https://api.cloudinary.com/v1_1/${process.env.NEXT_PUBLIC_CLOUD_NAME}/image/upload`, formData);
    setImage(response.data.secure_url);
    form.setValue('image', response.data.secure_url);
    setUploading(false);
  };
  const handleButtonClick = () => {
    if (fileInputRef.current) {
      fileInputRef.current.click();
    }
  };
  const handleImageDelete = () => {
    setImage('');
    form.setValue('image', '');
  };
  return (
    <div>
      <FormField
        control={form.control}
        name="image"
        render={() => (
          <FormItem className="relative" data-testid="image-input-container">
            <FormLabel className="text-xs" data-testid="image-input-label">
              Зураг оруулах <span className="text-red-500">*</span>
            </FormLabel>
            <FormControl>
              <div className="mt-4 relative group">
                {image ? (
                  <div className="relative" data-testid="image-preview-container">
                    <img src={image} className="w-full h-[160px] rounded-sm bg-secondary" alt="Event Image" data-testid="image-preview" />
                    <button
                      type="button"
                      onClick={handleImageDelete}
                      className="absolute top-2 right-2 p-1 text-gray-500 rounded-full opacity-0 group-hover:opacity-100 transition-opacity"
                      data-testid="delete-image-button"
                    >
                      <X className="w-5 h-5" />
                    </button>
                  </div>
                ) : uploading ? (
                  <div className="w-full h-[160px] bg-gray-200 flex items-center justify-center rounded-sm" data-testid="image-upload-loading">
                    <Loader />
                  </div>
                ) : (
                  <div className="w-full h-[160px] bg-gray-200 flex items-center justify-center rounded-sm" data-testid="image-upload-button-container">
                    <button
                      type="button"
                      onClick={handleButtonClick}
                      className="p-2 rounded-sm absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2"
                      data-testid="image-upload-button"
                    >
                      <span className="text-blue-600"> +</span>
                      <br /> Зураг оруулах
                    </button>
                  </div>
                )}
                <Input
                  ref={fileInputRef}
                  type="file"
                  accept="image/*"
                  style={{ display: 'none' }}
                  onChange={(e) => {
                    if (e.target.files) {
                      handleImageUpload(e.target.files[0]);
                    }
                  }}
                  data-testid="file-input"
                />
              </div>
            </FormControl>
          </FormItem>
        )}
      />
    </div>
  );
};

export default InputImage;
