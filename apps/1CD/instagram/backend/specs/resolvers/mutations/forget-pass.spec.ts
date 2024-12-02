import { GraphQLResolveInfo } from 'graphql';
import { forgetPassword } from '../../../src/resolvers/mutations/forget-password';
import { userModel } from '../../../src/models/user.model';
import crypto from 'crypto';

import { sendResetPassUrlToMail } from '../../../src/utils/sendmail';

jest.mock('../../../src/models/user.model', () => ({
  userModel: { findOne: jest.fn() },
}));

jest.mock('crypto', () => ({
  randomBytes: jest.fn(() => 'resetToken'),
  createHash: jest.fn().mockReturnThis(),
  update: jest.fn().mockReturnThis(),
  digest: jest.fn().mockReturnValue('hashedResetToken'),
}));

jest.mock('../../../src/utils/sendmail', () => ({ sendResetPassUrlToMail: jest.fn() }));

describe('forget-password', () => {
  it('Should throw error if user not exist', async () => {
    (userModel.findOne as jest.Mock).mockResolvedValueOnce(null);
    try {
      await forgetPassword!({}, { input: { email: 'test@gmail.com' } }, { userId: null }, {} as GraphQLResolveInfo);
    } catch (error) {
      expect(error).toEqual(new Error('Can not find this email address'));
    }
  });
  it('Should find user and update users reset token then send reset password link to user email', async () => {
    const mockUserModel = { _id: '1', email: 'test@gmail.com', resetPasswordToken: '', resetPasswordTokenExpire: null, save: jest.fn() };
    (userModel.findOne as jest.Mock).mockResolvedValueOnce(mockUserModel);
    (crypto.randomBytes as jest.Mock).mockReturnValueOnce('resetToken');
    await forgetPassword!({}, { input: { email: 'test@gmail.com' } }, { userId: null }, {} as GraphQLResolveInfo);
    expect(crypto.createHash).toHaveBeenCalledWith('sha256');
    // (crypto.update as jest.Mock).mockReturnValueOnce('resetToken')
    // expect(crypto.update).toHaveBeenCalledWith('resetToken');
    // expect(crypto.digest).toHaveBeenCalledWith('hex');
    expect(mockUserModel.resetPasswordToken).toBe('hashedResetToken');
    expect(mockUserModel.resetPasswordTokenExpire).toBeInstanceOf(Date);
    expect(mockUserModel.save).toHaveBeenCalled();
    expect(sendResetPassUrlToMail).toHaveBeenCalledWith('test@gmail.com', 'resetToken');
    // expect(result).toEqual(mockUserModel);
  });
});
