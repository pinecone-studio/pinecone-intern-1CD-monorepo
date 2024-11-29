import { GraphQLError } from 'graphql';
import { checkOtpDate } from '../../../src/utils/user/check-otp-expiration';

describe('check whether otp is expired or not', () => {
  it('should return user when otp is valid', () => {
    const currentTime = new Date();
    const user = {
      createdAt: new Date(currentTime.getTime() - 3 * 60 * 1000),
    };
    const res = checkOtpDate(user);
    expect(res).toBe('otp is valid');
  });
  it('should return error when otp is invalid', async () => {
    const currentTime = new Date();
    const user = {
      createdAt: new Date(currentTime.getTime() - 6 * 60 * 1000),
    };
    expect(() => checkOtpDate(user)).toThrow(GraphQLError);
    expect(() => checkOtpDate(user)).toThrow('failed otp');
  });
});