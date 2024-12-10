import { GraphQLError, GraphQLResolveInfo } from 'graphql';
import { userModel } from '../../../../src/models';
import { verifyOtp } from '../../../../src/resolvers/mutations';
import { checkOtpDate } from '../../../../src/utils/user/check-otp-expiration';
import { createTokenandCookie } from '../../../../src/utils/user/create-token-cookie';

jest.mock('../../../../src/models', () => ({
  userModel: {
    findOne: jest.fn(),
  },
}));

jest.mock('../../../../src/utils/user/check-otp-expiration', () => ({
  checkOtpDate: jest.fn(),
}));



jest.mock('../../../../src/utils/user/create-token-cookie',()=>({
  createTokenandCookie:jest.fn()
}))

describe('verifying the otp', () => {
  const mockEmail = 'test@gmail.com';
  const mockOtp = '1234';
  const mockInfo = {} as GraphQLResolveInfo;

  it('should return email when otp is verified', async () => {
    const mockUser = {
      email: mockEmail,
      otp: mockOtp,
      createdAt: Date.now(),
    };

    (userModel.findOne as jest.Mock).mockResolvedValue(mockUser);
    (checkOtpDate as jest.Mock).mockReturnValue('otp is valid');
    (createTokenandCookie as jest.Mock).mockResolvedValue('Token is created and set in the cookie');

    const res = await verifyOtp!({}, { input: { email: mockEmail, otp: mockOtp } }, {}, mockInfo);
    expect(checkOtpDate).toHaveBeenCalledWith(mockUser);
    expect(createTokenandCookie).toHaveBeenCalledWith(mockUser);
    expect(res).toEqual({ email: mockEmail });
  });

  it('should throw error when input is empty', async () => {
    await expect(verifyOtp!({}, { input: { email: '', otp:mockOtp} }, {}, mockInfo)).rejects.toThrow(GraphQLError);
    await expect(verifyOtp!({}, { input: { email: '', otp: mockOtp } }, {}, mockInfo)).rejects.toThrow('Email or Otp are required');
  });

  it('should throw error when user is not found', async () => {
    (userModel.findOne as jest.Mock).mockResolvedValue(null);
    await expect(verifyOtp!({}, { input: { email: mockEmail, otp: mockOtp } }, {}, mockInfo)).rejects.toThrow(GraphQLError);
    await expect(verifyOtp!({}, { input: { email: mockEmail, otp: mockOtp } }, {}, mockInfo)).rejects.toThrow('USER_NOT_FOUND');
  });
});
