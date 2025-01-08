'use client';
import CreateEventModal from './_components/EvenModal';
import { Container } from '@/components/Container';
import { AdminDashboard } from './_components/AdminDashboard';
import { useGetEventsQuery } from '@/generated';
import { useAuth } from '@/components/providers';
import { useQueryState } from 'nuqs';
import { Event, useGetEventsLazyQuery } from '@/generated';
import { useEffect } from 'react';
import { useDebounce } from '@uidotdev/usehooks';
import { Input } from '@/components/ui/input';
import { Search } from 'lucide-react';
import DatePicker from './_components/DatePicker2';

const HomePage = () => {
  const { user } = useAuth();

  const { refetch } = useGetEventsQuery();
  const [q, setQ] = useQueryState('q', { defaultValue: '' });
  const [artist, setArtist] = useQueryState('artist', { defaultValue: '' });
  const [date] = useQueryState('date', { defaultValue: '' });

  const debouncedQ = useDebounce(q, 300);

  const [getEvents1, { data }] = useGetEventsLazyQuery();

  useEffect(() => {
    getEvents1({
      variables: {
        filter: {
          q: debouncedQ,
          artist: artist,
          date: date,
        },
      },
    });
  }, [debouncedQ, artist, date]);

  if (!user || user.role !== 'admin') {
    return (
      <div
        className="flex flex-col items-center justify-center w-full min-h-full bg-black"
        style={{
          background: 'radial-gradient(32.61% 32.62% at 50% 125%, #00B7F4 0%, #0D0D0F 100%)',
        }}
      >
        <p className="text-xl text-center text-white">
          Админ эрхтэй мэйл хаягаар <br /> нэвтэрч цааш үргэлжлүүлнэ үү!
        </p>
      </div>
    );
  }

  return (
    <Container>
      <div data-testid="Admin-Dash" className="admin-dash min-h-[calc(100vh-140px)] py-9">
        <div className="flex justify-between w-full text-center text-black h-fit">
          <div className="flex flex-col items-start gap-[1px ]">
            <h3 className="text-lg">Тасалбар</h3>
            <p className="text-sm text-[#71717A]">Идэвхитэй зарагдаж буй тасалбарууд</p>
          </div>
          <CreateEventModal refetch={refetch} />
        </div>
        <div className="border-t-[1px] my-6"></div>
        <div className="flex gap-2">
          <div className="relative flex items-center w-[263px] ">
            <Input data-testid="Search-Input" type="text" placeholder="Хайлт" className="w-full text-xs border-gray-600 " value={q} onChange={(e) => setQ(e.target.value)} />
            <Search className="absolute w-4 h-4 right-4 color-white" />
          </div>
          <div className="relative flex items-center  w-[263px]">
            <Input
              data-testid="Artist-Search-Input"
              type="text"
              placeholder="Уран бүтээлчээр хайх"
              className="w-full border-gray-600 md:w-80"
              value={artist}
              onChange={(e) => setArtist(e.target.value)}
            />
            <Search className="absolute w-4 h-4 right-4" />
          </div>
          <DatePicker />
        </div>

        <AdminDashboard data={data?.getEvents as Event[]} refetch={refetch} />
      </div>
    </Container>
  );
};

export default HomePage;
