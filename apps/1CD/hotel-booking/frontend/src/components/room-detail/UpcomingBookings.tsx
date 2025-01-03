import { Badge } from '@/components/ui/badge';
import { Card, CardHeader } from '@/components/ui/card';
import { Table, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';

import React from 'react';

const UpcomingBookings = () => {
  return (
    <Card className="w-[780px] h-[450px] px-4">
      <CardHeader className="font-semibold">Upcoming Bookings</CardHeader>
      <Table className="border rounded-xl">
        <TableHeader className="bg-gray-100">
          <TableRow className="flex items-center gap-4 border-t rounded-xl">
            <TableHead className="flex items-center h-6 pl-5 font-semibold text-black border-r-[1px] w-28">ID</TableHead>
            <TableHead className="flex items-center border-r-[1px] h-9 w-1/2 font-semibold text-black">Guest name</TableHead>
            <TableHead className="flex items-center border-r-[1px] h-9 w-40 font-semibold text-black">Status</TableHead>
            <TableHead className="flex items-center border-r-[1px] h-9 w-60 font-semibold text-black">Date</TableHead>
          </TableRow>
        </TableHeader>
        <TableRow className="flex gap-4 border border-b-xl">
          <TableCell className="border-r-[1px] w-28">001</TableCell>
          <TableCell className="border-r-[1px] w-1/2">Shagai Nyamdorj</TableCell>
          <TableCell className="border-r-[1px] w-40">
            <Badge className="flex items-center justify-center w-24 bg-blue-600">Booked</Badge>
          </TableCell>
          <TableCell className="border-r-[1px] w-60">Oct-21 </TableCell>
        </TableRow>
        <TableRow className="flex gap-4 border border-b-xl">
          <TableCell className="border-r-[1px] w-28">001</TableCell>
          <TableCell className="border-r-[1px] w-1/2">Shagai Nyamdorj</TableCell>
          <TableCell className="border-r-[1px] w-40">
            <Badge className="flex items-center justify-center w-24 bg-blue-600">Booked</Badge>
          </TableCell>
          <TableCell className="border-r-[1px] w-60">Oct-21 </TableCell>
        </TableRow>
      </Table>
    </Card>
  );
};

export default UpcomingBookings;
