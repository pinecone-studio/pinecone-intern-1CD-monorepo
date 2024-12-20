'use client';

import { useRouter } from 'next/navigation';

const Header = () => {
  const router = useRouter();

  return (
    <div className="relative flex flex-col w-full gap-4 mb-20">
      <div className="bg-[#013B94] py-4 min-h-[230px] md:min-h-[250px]">
        <div className="max-w-[1450px] w-full px-4 mx-auto sm:px-6 lg:px-8">
          <div className="flex flex-col items-center justify-between space-y-4 sm:flex-row sm:space-y-0">
            <div className="flex items-center gap-2">
              <div className="w-5 h-5 bg-white rounded-full"></div>
              <p className="text-lg font-medium text-white">Pedia</p>
            </div>
            <div className="flex gap-4">
              <button
                onClick={() => {
                  router.push('/signup');
                }}
              >
                <p className="text-sm font-medium text-[#FAFAFA] cursor-pointer hover:opacity-80">Register</p>
              </button>
              <button
                onClick={() => {
                  router.push('/login');
                }}
              >
                <p className="text-sm font-medium text-[#FAFAFA] cursor-pointer hover:opacity-80">Sign in</p>
              </button>
            </div>
          </div>

          <div className="text-center text-white pt-14 ">
            <h2 className="mb-2 text-2xl font-semibold sm:text-3xl">Find the Best Hotel for Your Stay</h2>
            <p className="text-xs font-light sm:text-sm text-gray-50">Book from a wide selection of hotels for your next trip</p>
          </div>

          <div className="mt-4 sm:absolute sm:transform sm:-translate-x-1/2 sm:-translate-y-4 sm:top-1/2 sm:left-1/2">{/* <HeaderFilter /> */}</div>
        </div>
      </div>
    </div>
  );
};

export default Header;
