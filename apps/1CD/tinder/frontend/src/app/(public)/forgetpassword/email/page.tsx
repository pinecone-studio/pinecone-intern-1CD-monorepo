'use client';
import { Button } from '@/components/ui/button';

import { Input } from '@/components/ui/input';
import { useCheckEmailMutation } from '@/generated';

import Image from 'next/image';
import { useRouter } from 'next/navigation';
import { useState } from 'react';
import { toast } from 'sonner';

const CheckEmail = () => {
  const [email, setEmail] = useState<string>('');
  const router = useRouter();

  const [checkEmail, { loading }] = useCheckEmailMutation({
    onCompleted: (data) => {
      router.push('/forgetpassword/otp');
      localStorage.setItem('userEmail', data.checkEmail.email);
    },
    onError: (error) => {
      toast.error(error.message);
    },
    variables: {
      input: { email },
    },
  });

  return (
    <div data-cy="forgetpassword-page-container" className="min-h-screen flex flex-col items-center justify-center bg-white pt-[200px]">
      <div data-cy="forgetpassword-email-header" className="flex gap-2">
        <Image src="../logo.svg" width={20} height={24} alt="logo" className="w-5 h-6" />

        <div className="text-[#424242] font-bold text-2xl">tinder</div>
      </div>
      <div className="w-full max-w-md px-6">
        <h1 className="text-center text-[#09090B] font-semibold text-2xl">Forget password</h1>
        <p className="text-center text-gray-500 text-sm mb-6">Enter your email account to reset password</p>

        <div>
          <div className="block text-sm text-gray-600 mb-1 pt-1">Email</div>
          <Input
            data-cy="forgetpassword-email-input"
            type="email"
            placeholder="name@example.com"
            className="w-full px-4 py-3 rounded-lg border border-gray-300 focus:outline-none focus:border-pink-500"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
        </div>
        <div className="py-2">
          <Button
            data-cy="forgetpassword-continue-button"
            type="submit"
            className="w-full bg-[#fd5b6d] hover:bg-[#fd4b5d] text-white py-4 rounded-full font-medium transition duration-200"
            onClick={() => checkEmail()}
            disabled={loading}
          >
            Continue
          </Button>
        </div>
      </div>
      <div className="mt-auto py-6 text-gray-400 text-sm ">©2024 Tinder</div>
    </div>
  );
};

export default CheckEmail;
