'use client';

import { format } from 'date-fns';
import { Calendar as CalendarIcon } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Calendar } from '@/components/ui/calendar';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { useQueryState } from 'nuqs';
import { DateRange } from 'react-day-picker';
import { useEffect, useState } from 'react';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export const DatePickerWithRange = ({ className }: React.HTMLAttributes<HTMLDivElement>) => {
  const [dateFromQuery, setDateFrom] = useQueryState('dateFrom');
  const [dateToQuery, setDateTo] = useQueryState('dateTo');
  const [date, setDate] = useState<DateRange | undefined>();
  const dateFromParsed = dateFromQuery ? new Date(dateFromQuery) : null;
  const dateToParsed = dateToQuery ? new Date(dateToQuery) : null;

  useEffect(() => {
    if (date?.from && date.to) {
      setDateFrom(date?.from?.toISOString());
      setDateTo(date?.to?.toISOString());
    }
  }, [date]);
  return (
    <div data-cy="Date-Picker-Modal" className={cn('grid gap-2 min-w-[500px]', className)}>
      <Popover>
        <PopoverTrigger data-cy="Trigger-Test" asChild>
          <Button data-testid="Date-Picker-Btn" id="date" variant={'outline'} className={cn('w-[500px] justify-between text-left font-normal')}>
            {dateFromParsed && dateToParsed ? (
              <>
                {format(dateFromParsed, 'LLL dd, y')} - {format(dateToParsed, 'LLL dd, y')}
              </>
            ) : (
              <>Please enter filter date</>
            )}
            <CalendarIcon className="w-4 h-4 ml-2 opacity-50" />
          </Button>
        </PopoverTrigger>
        <PopoverContent className={cn('w-auto p-0', 'max-w-[600px]', 'overflow-x-auto')} align="start">
          <Calendar
            data-cy="Date-Picker-Calendar"
            initialFocus
            mode="range"
            defaultMonth={date?.from}
            selected={date}
            onSelect={setDate}
            numberOfMonths={2}
            className={cn('max-w-full', 'overflow-x-auto', 'block')}
          />
        </PopoverContent>
      </Popover>
    </div>
  );
};
