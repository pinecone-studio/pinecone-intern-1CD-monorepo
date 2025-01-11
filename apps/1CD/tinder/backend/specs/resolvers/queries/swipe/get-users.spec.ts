
import { getUsers } from '../../../../src/resolvers/queries';
import { userModel, swipeModel } from '../../../../src/models';
import { GraphQLError, GraphQLResolveInfo } from 'graphql';

jest.mock('../../../../src/models', () => ({
  userModel: {
    findById: jest.fn(),
    find: jest.fn(),
  },
  swipeModel: {
    find: jest.fn(),
  },
}));

describe('getUsers Query', () => {
  const mockUserId = 'user123';

  it('should throw an error if user is not found', async () => {
    (userModel.findById as jest.Mock).mockResolvedValue(null);

    await expect(getUsers!({}, {}, { userId: mockUserId }, {} as GraphQLResolveInfo))
      .rejects.toThrow(GraphQLError);
  });

  it('should return all users when attraction is "both"', async () => {
    const mockUser = { _id: mockUserId, attraction: 'both' };
    const mockUsers = [{ _id: 'user1' }, { _id: 'user2' }];

    (userModel.findById as jest.Mock).mockResolvedValue(mockUser);
    (swipeModel.find as jest.Mock).mockResolvedValue([]);
    (userModel.find as jest.Mock).mockResolvedValue(mockUsers);

    const result = await getUsers!({}, {}, { userId: mockUserId }, {} as GraphQLResolveInfo);

    expect(result).toEqual(mockUsers);

  });

  it('should filter users based on attraction', async () => {
    const mockUser = { _id: mockUserId, attraction: 'female' };
    const mockUsers = [{ _id: 'user1', gender: 'female' }];

    (userModel.findById as jest.Mock).mockResolvedValue(mockUser);
    (swipeModel.find as jest.Mock).mockResolvedValue([]);
    (userModel.find as jest.Mock).mockResolvedValue(mockUsers);

    const result = await getUsers!({}, {}, { userId: mockUserId }, {} as GraphQLResolveInfo);

    expect(result).toEqual(mockUsers);
  
  });

  it('should exclude swiped users', async () => {
    const mockUser = { _id: mockUserId, attraction: 'male' };
    const swipedUsers = [{ swipedUser: 'swipedUser1' }];
    const mockUsers = [{ _id: 'user2', gender: 'male' }];

    (userModel.findById as jest.Mock).mockResolvedValue(mockUser);
    (swipeModel.find as jest.Mock).mockResolvedValue(swipedUsers);
    (userModel.find as jest.Mock).mockResolvedValue(mockUsers);

    const result = await getUsers!({}, {}, { userId: mockUserId }, {} as GraphQLResolveInfo);

    expect(result).toEqual(mockUsers);
   
  });
});
