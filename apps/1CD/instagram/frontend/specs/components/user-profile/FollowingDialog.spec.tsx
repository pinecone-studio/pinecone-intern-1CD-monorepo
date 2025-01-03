import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { expect } from '@jest/globals';
import FollowingDialog from '@/components/user-profile/FollowingDialog';
const mockedFollowingData = [{ _id: '1', fullName: 'Mock User1', profileImg: 'http://www.example.com/proImage1.jpg', userName: 'MockiU' }];
describe('render followers dialog', () => {
  it('1. should render successfully', async () => {
    render(<FollowingDialog followingData={mockedFollowingData} followingDataCount={mockedFollowingData.length} />);
  });
  it('2. should show followers dialog when click in followers', async () => {
    render(<FollowingDialog followingData={mockedFollowingData} followingDataCount={mockedFollowingData.length} />);
    const trigger = screen.getByTestId('followingNumber');
    fireEvent.click(trigger);
    await waitFor(() => expect(screen.getByTestId('followingDialog')).toBeDefined());
  });

  it('3. close the dialog when close button is clicked', async () => {
    render(<FollowingDialog followingData={mockedFollowingData} followingDataCount={mockedFollowingData.length} />);
    const trigger = screen.getByTestId('followingNumber');
    fireEvent.click(trigger);
    await waitFor(() => expect(screen.getByTestId('followingDialog')).toBeDefined());
    // const closeButtonFollowing = screen.getByTestId('closeButtonFollowing');
    // fireEvent.click(closeButtonFollowing);
  });
});
