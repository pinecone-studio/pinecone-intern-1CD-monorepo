import { updateAttraction } from '../../../../src/resolvers/mutations';
import { GraphQLResolveInfo } from 'graphql';
import { userModel } from '../../../../src/models';

jest.mock('../../../../src/models', () => ({
  userModel: {
    findOne: jest.fn(),
    findOneAndUpdate: jest.fn(),
  },
}));

describe('update attraction', () => {
  const mockUser = {
    email: 'sara@gmail.com',
  };

  const updatedAttraction = {
    email: 'sara@gmail.com',
  };

  it('should update attraction', async () => {
    (userModel.findOne as jest.Mock).mockResolvedValue(mockUser);
    (userModel.findOneAndUpdate as jest.Mock).mockResolvedValue(updatedAttraction);
    const result = await updateAttraction!(
      {},
      {
        email: 'nara@gmail.com',
        attraction: 'female',
      },
      {},
      {} as GraphQLResolveInfo
    );
    expect(result).toEqual(updatedAttraction);
  });
  it('should throw error', async () => {
    (userModel.findOne as jest.Mock).mockResolvedValue(null);

    expect(updateAttraction!({}, { email: 'nara@gmail.com', attraction: 'female' }, {}, {} as GraphQLResolveInfo)).rejects.toThrow('user not found');
  });
  it('should throw error', async () => {
    expect(updateAttraction!({}, { email: 'nara@gmail.com', attraction: '' }, {}, {} as GraphQLResolveInfo)).rejects.toThrow('attraction is empty');
  });
});
