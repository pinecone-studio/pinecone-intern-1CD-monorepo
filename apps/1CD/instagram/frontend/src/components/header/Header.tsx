'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { MenuBar } from './MenuBar';
import Image from 'next/image';

import { Instagram } from 'lucide-react';

export const Header = () => {
  const [hide, setHide] = useState(false);
  return (
    <aside
      data-testid="header"
      className={`relative h-screen flex-none border-r bg-card 
     ${hide ? 'w-20' : 'w-[260px]'}
       overflow-hidden`}
    >
      <div className="p-5 pt-10 ">
        <Link href="/" className="">
          <div className={`relative w-[100px] h-[30px] flex items-center `}>
            <Image alt="Logo" src="/images/Logo.png" fill={true} className={`w-auto h-auto ${hide ? 'hidden' : ''}  `} sizes="w-auto h-auto" priority />
            <p className={` ${hide ? 'pl-2 inline-flex justify-center' : 'hidden'} text-2x  `}>
              {' '}
              <Instagram />
            </p>
          </div>
        </Link>
      </div>

      <div className="mt-12 px-7 ">
        <MenuBar hide={hide} setHide={setHide} />
      </div>
    </aside>
  );
};
