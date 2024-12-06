'use client';

import Image from 'next/image';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Separator } from '@/components/ui/separator';
import { useRegisterEmailMutation } from '@/generated';
import { Toaster } from '@/components/ui/sonner';
import { toast } from 'sonner';

import { useRouter } from 'next/navigation';
import { useState } from 'react';

const Register = () => {
  const [email, setEmail] = useState<string>('');

  const [registerEmail, { loading }] = useRegisterEmailMutation({
    onCompleted: (data) => {
      toast.success(`Success! We've sent a verification otp to ${data.registerEmail.email}. Please check your inbox.`);
      localStorage.setItem('useEmail', data.registerEmail.email);
      router.push('/register/otp');
    },
    onError: (error) => {
      toast.error(error.message);
    },
    variables: {
      input: {
        email,
      },
    },
  });
  const router = useRouter();



  return (
    <div data-cy="register-page-container" className="pt-[200px] justify-items-center">
      <div data-cy="register-email-header" className="flex items-center gap-1">
        <Image src="../logo.svg" width={20} height={24} alt="logo" className="w-5 h-6" />
        <div className="text-[#424242] font-bold text-2xl">tinder</div>
      </div>
      <div className="text-[#09090B] font-semibold text-2xl pt-6 ">Create an account</div>
      <div className="text-[#71717A] text-sm font-normal pt-1">Enter your email below to create your account</div>
      <div className="pt-6">
        <div className="text-[#09090B] font-medium text-sm pb-2">Email</div>
        <Input data-cy="register-email-input" placeholder="name@example.com" className="w-[350px] border-[#E4E4E7] border-2" value={email} onChange={(e) => setEmail(e.target.value)} />
        <Button data-cy="register-continue-button" className="w-[350px] h-9 bg-[#E11D48E5] rounded-full text-[#FAFAFA] text-sm font-medium mt-4" onClick={() => registerEmail()} disabled={loading}>
          Continue
        </Button>
        <div className="flex">
          <Separator className="my-8 w-[145px]" color="#E4E4E7" />
          <div className="my-6 text-[#71717A] font-normal text-xs mx-5">OR</div>
          <Separator className="my-8 w-[145px]" color="#E4E4E7" />
        </div>
        <Toaster />

        <Button className="w-[350px] h-9 bg-white border-[#E4E4E7] rounded-full text-[#18181B] hover:bg-white border-2 text-sm font-medium mt-4">Log in</Button>
        <div className="text-[#71717A] font-normal text-sm pt-6 text-center">By clicking continue, you agree to our</div>
        <div className="text-[#71717A] font-normal text-sm text-center underline-offset-1 underline">Terms of Service and Privacy Policy.</div>
      </div>
    </div>
  );
};
export default Register;
