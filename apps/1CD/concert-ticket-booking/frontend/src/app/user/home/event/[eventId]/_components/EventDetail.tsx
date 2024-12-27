'use client';
import { Event } from '@/generated';
import dayjs from 'dayjs';
import Image from 'next/image';
import React, { useEffect, useState } from 'react';
import { CiCalendar, CiLocationOn } from 'react-icons/ci';
import { IoMdTime } from 'react-icons/io';

const EventDetail = ({ event }: { event: Event }) => {
  const [openDoorTime, setOpenDoorTime] = useState<string | null>(null);
  const [musicStartTime, setMusicStartTime] = useState<string | null>(null);
  useEffect(() => {
    if (event?.scheduledDays && event.scheduledDays.length > 0) {
      const scheduledTime = dayjs(event.scheduledDays[0]);
      const doorOpenTime = scheduledTime.subtract(2, 'hour').format('hh:mm A');
      setOpenDoorTime(doorOpenTime);
    }
  }, [event]);
  useEffect(() => {
    if (event?.scheduledDays && event.scheduledDays.length > 0) {
      const scheduledTime = dayjs(event.scheduledDays[0]);
      const startTime = scheduledTime.add(2, 'hour').format('hh:mm A');
      setMusicStartTime(startTime);
    }
  }, [event]);

  return (
    <div className="flex justify-around max-w-[533px]" data-cy="Event-Detail">
      <div className="flex flex-col gap-6">
        <div className="flex justify-between ">
          <div className="flex gap-6">
            <div className="flex items-center gap-2" data-cy="Scheduled-Days">
              <CiCalendar className="w-4 h-4 text-gray-400" />
              {event?.scheduledDays.length > 1 ? (
                <span className="flex items-center text-base text-white" data-cy="Scheduled-Days-Range">
                  {dayjs(event.scheduledDays[0]).format('YYYY.MM.DD')} - {dayjs(event.scheduledDays[event.scheduledDays.length - 1]).format('MM.DD')}
                </span>
              ) : (
                event?.scheduledDays.map((day, index) => (
                  <span className="flex items-center text-base text-white" key={index} data-cy={`Scheduled-Day-${index}`}>
                    {dayjs(day).format('YY.MM.DD')}
                  </span>
                ))
              )}
            </div>
            <div className="flex items-center gap-2" data-cy="Scheduled-Time">
              <IoMdTime className="w-4 h-4 text-gray-400" />
              <span className="text-base text-white">{event?.scheduledDays.length > 0 && <span className="flex items-center">{dayjs(event.scheduledDays[0]).format('hh:mm A')}</span>}</span>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <CiLocationOn className="w-4 h-4 text-gray-400" />
            <span className="text-base text-white" data-cy="Venue-Name">
              {event?.venue.name}
            </span>
          </div>
        </div>
        <div className="flex flex-col gap-2">
          <div data-cy="Special-Artist">
            <h1 className="text-sm font-light text-zinc-50">Special Artist:</h1>
            {event?.guestArtists?.map((guest, index) => (
              <span className="text-sm font-semibold text-white" key={index} data-cy={`Guest-Artist-${index}`}>
                {guest?.name}
              </span>
            ))}
          </div>
          <div data-cy="Schedule-Time-Details">
            <h1 className="text-sm font-light text-zinc-50">Тоглолтын цагийн хуваарь:</h1>
            <ul>
              <li className="text-sm font-semibold text-white" data-cy="Door-Open-Time">
                Door Open: {openDoorTime}
              </li>
              <li className="text-sm font-semibold text-white" data-cy="Music-Start-Time">
                Music Start: {musicStartTime}
              </li>
            </ul>
          </div>
          <div data-cy="Event-Description">
            <p className="text-sm font-light text-zinc-50">Тоглолтын дэлгэрэнгүй:</p>
            <span className="text-sm font-semibold text-white">{event?.description}</span>
          </div>
          <div className="flex flex-col gap-2">
            <h1 className="text-sm font-medium text-zinc-50" data-cy="Stage-Plan-Title">
              Stage plan:
            </h1>
            <div data-cy="Stage-Plan">
              <Image src="/images/stagePlan.png" alt="Stage" width={533} height={413} />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default EventDetail;
