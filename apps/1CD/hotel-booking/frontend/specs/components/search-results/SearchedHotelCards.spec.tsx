import { render } from '@testing-library/react';
import { SearchedHotelCards } from '@/components/search-hotel/SearchedHotelCards';

describe('Searched hotel room cards', () => {
  it('should render', async () => {
    render(<SearchedHotelCards />);
  });
});
