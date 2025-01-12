'use client';

import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';

export const UserdetailsBio = ({ formik }: any) => {
  return (
    <div className="sm:grid sm:w-full sm:max-w-sm sm:items-center sm:gap-1.5 flex flex-col w-[350px] gap-1.5">
      <Label htmlFor="bio" className="text-[#09090B] font-medium text-sm">
        Bio
      </Label>
      <Textarea id="bio" placeholder="Tell us about yourself" value={formik.values.bio} onChange={formik.handleChange} onBlur={formik.handleBlur} data-cy="User-Details-Bio-Input" />
      {formik.errors.bio && formik.touched.bio && (
        <span className="text-red-600" data-cy="User-Details-Bio-Input-Error-Message">
          {formik.errors.bio}
        </span>
      )}
    </div>
  );
};
