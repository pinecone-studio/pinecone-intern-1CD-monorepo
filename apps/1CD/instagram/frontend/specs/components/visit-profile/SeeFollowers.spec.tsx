import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { expect } from '@jest/globals';
import SeeFollowersDialog from '@/components/visit-profile/SeeFollowers';
const mockedFollowerData = [{ _id: '1', fullName: 'Mock User1', profileImg: 'http://www.example.com/proImage1.jpg', userName: 'MockiU' }];
describe('render followers dialog', () => {
  it('1. should render successfully', async () => {
    render(<SeeFollowersDialog followerData={mockedFollowerData} followerDataCount={mockedFollowerData.length} />);
  });
  it('2. should show followers dialog when click in followers', async () => {
    render(<SeeFollowersDialog followerData={mockedFollowerData} followerDataCount={mockedFollowerData.length} />);
    const trigger = screen.getByTestId('followerNumber');
    fireEvent.click(trigger);
    await waitFor(() => expect(screen.getByTestId('followerDialog')).toBeDefined());
  });

  it('3. close the dialog when close button is clicked', async () => {
    render(<SeeFollowersDialog followerData={mockedFollowerData} followerDataCount={mockedFollowerData.length} />);
    const trigger = screen.getByTestId('followerNumber');
    fireEvent.click(trigger);
    await waitFor(() => expect(screen.getByTestId('followerDialog')).toBeDefined());
  });
});
