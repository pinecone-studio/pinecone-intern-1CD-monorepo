'use client';

import * as React from 'react';
import { ChevronDown } from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';

export const ComboboxDemo = () => {
  const [open, setOpen] = React.useState(false);
  const [adultQuantity, setAdultQuantity] = React.useState(1);

  const descBtn = () => {
    if (adultQuantity > 1) {
      setAdultQuantity(adultQuantity - 1);
    }
  };

  const closeModal = () => {
    setOpen(false);
  };

  return (
    <div data-cy="Adult-Select-Modal" className="w-full mx-auto xl:min-w-[500px]">
      <Popover open={open} onOpenChange={setOpen}>
        <PopoverTrigger asChild>
          <Button data-testid="traveler-select-btn" variant="outline" role="combobox" className="justify-between w-full max-w-md" onClick={() => setOpen(!open)} data-cy="Adult-Select-Modal-Button">
            {adultQuantity} traveler{adultQuantity > 1 ? 's' : ''}, 1 room
            <ChevronDown className="opacity-50" />
          </Button>
        </PopoverTrigger>

        <PopoverContent className="relative xl:min-w-[450px] p-0  min-h-44">
          <h3 className="mt-5 ml-4 text-lg font-bold sm:ml-6 sm:text-xl">Travels</h3>
          <div className="flex items-center justify-between px-4 sm:pr-6 border-b-[1px] mx-2 sm:mx-4 pb-3">
            <p className="mt-5 ml-2 sm:ml-6">Adult</p>
            <div className="flex items-center gap-2 sm:gap-4">
              <button className="flex items-center justify-center w-8 h-8 border sm:w-10 sm:h-10 rounded-xl" onClick={descBtn} data-cy="Adult-Quantity-Desc-Button">
                -
              </button>
              <p data-cy="Adult-Quantity" className="text-lg sm:text-xl">
                {adultQuantity}
              </p>
              <button
                data-cy="Adult-Quantity-Increase-Button"
                className="flex items-center justify-center w-8 h-8 border sm:w-10 sm:h-10 rounded-xl"
                onClick={() => setAdultQuantity(adultQuantity + 1)}
              >
                +
              </button>
            </div>
          </div>
          <button data-cy="Modal-Done-Button" className="absolute w-24 px-4 py-2 my-4 text-white bg-blue-700 rounded-md sm:my-5 sm:w-28 right-4 sm:right-5" onClick={closeModal}>
            Done
          </button>
        </PopoverContent>
      </Popover>
    </div>
  );
};