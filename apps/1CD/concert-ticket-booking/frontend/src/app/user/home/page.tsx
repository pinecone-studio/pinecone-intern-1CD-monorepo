'use client';

import { useQueryState } from 'nuqs';
import CardTicket from '@/components/Card';
import { Event, useGetEventsLazyQuery, useGetEventsQuery } from '@/generated';
import { useEffect } from 'react';
import { useDebounce } from '@uidotdev/usehooks';

const Page = () => {
  const [q, setQ] = useQueryState('q', { defaultValue: '' });

  const debouncedQ = useDebounce(q, 300);

  const [getEvents1, { data, loading }] = useGetEventsLazyQuery();

  useEffect(() => {
    getEvents1({
      variables: {
        filter: {
          q: debouncedQ,
        },
      },
    });
  }, [debouncedQ]);

  console.log(data?.getEvents);

  return (
    <div className="w-full h-screen  bg-black pt-10" data-cy="Home-Page">
      <div className="xl:w-[1100px] md:w-[700px] w-[350px] mx-auto grid grid-cols-1 md:grid-cols-2  xl:grid-cols-3 gap-4 ">
        {loading && <div className="flex w-full h-full justify-center items-center">Loading...</div>}
        {data?.getEvents?.map((event) => (
          <div key={event?._id}>{event && <CardTicket event={event as Event} />}</div>
        ))}
      </div>
    </div>
  );
};
export default Page;
