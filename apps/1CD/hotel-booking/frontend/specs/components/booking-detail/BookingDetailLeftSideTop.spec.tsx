import BookingDetailLeftSideTop from '@/components/BookingDetailLeftSideTop';
import { BookingStatus } from '@/generated';

import { fireEvent, render } from '@testing-library/react';

describe('Booking detail view rules dialog', () => {
  const bookingmock = {
    _id: '6757dfb4687cb83ca69ff3cb',
    userId: '123',
    roomId: {
      id: '674851d9066230f0d7f74866',
      roomService: {
        bathroom: ['sds'],
        accessability: ['qqqq'],
        entertaiment: ['drink'],
        foodDrink: ['food'],
        bedroom: ['test'],
        other: ['busad'],
      },
      hotelId: {
        createdAt: '2024-12-01T06:01:58.398Z',
        _id: '674bfbd6a111c70660b55541',
        hotelName: 'Flower Hotel Ulaanbaatar',
        description: 'Ulaanbaatar hotel in Downtown Ulaanbaatar with 4 restaurants and a full-service spa',
        starRating: 5,
        userRating: 1,
        phoneNumber: 77700700,
        images: ['/https'],
        hotelAmenities: ['badral'],
      },
      roomName: 'badral',
      roomType: '1bed',
      price: 500000,
      roomInformation: 'luxury',
      createdAt: '2024-11-28T11:19:53.393Z',
    },
    hotelId: '674e7578b242c9e3bd9017d7',
    checkInDate: '2024-12-08T00:00:00.000Z',
    checkOutDate: '2024-12-12T00:00:00.000Z',
    totalPrice: 250000,
    status: BookingStatus.Booked,
  };
  it('it should render and click dialog close button', () => {
    const { getByTestId } = render(<BookingDetailLeftSideTop booking={bookingmock} />);
    const openCheckInDialog = getByTestId('Open-CheckIn-Dialog');
    const openViewRulesDialogButton = getByTestId('Open-View-Price-Details');
    fireEvent.click(openViewRulesDialogButton);
    fireEvent.click(openCheckInDialog);
  });
});
