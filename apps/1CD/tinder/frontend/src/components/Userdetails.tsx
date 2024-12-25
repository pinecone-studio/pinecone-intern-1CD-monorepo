'use client';

import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Button } from '@/components/ui/button';
import { useFormik } from 'formik';
import * as Yup from 'yup';
import { useUseDetails } from './providers/UserDetailsProvider';
import { UserdetailsBio } from './UserdetailsBio';
import { UserdetailsName } from './UserdetailsName';
import { UserdetailsProfession } from './UserdetailsProfession';
import { useEffect} from 'react';
import { toast } from 'sonner';
import Image from 'next/image';
import { useRouter} from 'next/navigation';
import { UserdetailsSchool } from './UserdetailsSchool';

const validationSchema = Yup.object({
  name: Yup.string().required('Name is required').min(2, 'Name length must be at least 2 characters'),
  bio: Yup.string().required('Bio is required'),
  interests: Yup.string().optional(),
  profession: Yup.string().required('Profession is required'),
  schoolWork: Yup.string().optional(),
});

const initialValues = {
  name: '',
  bio: '',
  interests: '',
  profession: '',
  schoolWork: '',
};

export const Userdetails = () => {
  const router = useRouter();
  const { updateUser, data, error } = useUseDetails();
  const back=()=>{
    router.push('/register/birthday')
  }
  useEffect(() => {
    if (data) {
      toast.success('Successfully added your information');
      router.push('/sign-up/image')
      return;
    }
    const message = error.cause?.message;
    if (message) {
      toast.error('Error occured. Try again');
      return;
    }
  }, [data, error]);

  const formik = useFormik({
    initialValues,
    validationSchema,
    onSubmit: async (values) => {
      try {
        const arrayofInterests = formik.values.interests.split(',').map((item) => item.trim());
        const arrayofSchool = formik.values.schoolWork.split(',').map((item) => item.trim());
        await updateUser({
          variables: {
            name: values.name,
            bio: values.bio,
            profession: values.profession,
            schoolWork: arrayofSchool,
            interests: arrayofInterests,
          },
        });
      } catch (error) {
        if (error) {
          toast.error('Internal server error. Try again');
        }
      }
      formik.resetForm();
    },
  });
  
  return (
    <div className=" flex flex-col justify-between items-center mt-10 h-screen" data-cy="User-Details-Page">
      <div className="flex flex-col justify-center items-center gap-6">
        <div data-cy="register-email-header" className="flex items-center gap-1">
          <Image src="../logo.svg" width={20} height={24} alt="logo" className="w-5 h-6" />
          <div className="text-[#424242] font-bold text-2xl">tinder</div>
        </div>
        <form className="flex flex-col gap-6 max-w-sm" onSubmit={formik.handleSubmit}>
          <div className="text-center">
            <p className="text-[#09090B] font-semibold text-2xl">Your Details</p>
            <p className="text-[#71717A] font-normal text-sm">Please provide the following information to help us get to know you better.</p>
          </div>
          <div className="flex flex-col gap-6">
            <UserdetailsName formik={formik} />
            <UserdetailsBio formik={formik} />
            <div className="grid w-full max-w-sm items-center gap-1.5">
              <Label htmlFor="interests" className="text-[#09090B] font-medium text-sm">
                Interests
              </Label>
              <Input
                type="text"
                id="interests"
                placeholder="Enter your interests (comma separated)"
                value={formik.values.interests}
                onChange={formik.handleChange}
                data-cy="User-Details-Interests-Input"
              />
              {formik.errors.interests && formik.touched.interests && (
                <span className="text-red-600" data-cy="User-Details-Interests-Input-Error-Message">
                  {formik.errors.interests}
                </span>
              )}
            </div>
            <UserdetailsProfession formik={formik} />
            <UserdetailsSchool formik={formik}/>
          </div>
          <div className="flex justify-between max-w-sm">
            <Button variant="outline" type="button" className="text-[#18181B] font-medium text-sm rounded-full" data-cy="User-Details-Back-Button" onClick={()=>back()}>
              Back
            </Button>
            <Button variant="destructive" type="submit" className="text-[#FAFAFA] font-medium text-sm rounded-full" disabled={!formik.dirty || !formik.isValid} data-cy="User-Details-Next-Button">
              Next
            </Button>
          </div>
        </form>
      </div>

      <p className="text-[#71717A] text-sm pb-[24px]">©2024 Tinder</p>
    </div>
  );
};