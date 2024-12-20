/* eslint-disable @typescript-eslint/no-non-null-assertion */
import { getPostLikes } from '../../../../src/resolvers/queries';
import { GraphQLResolveInfo } from 'graphql';

jest.mock('../../../../src/models/post.model', () => ({
  PostLikeModel: {
    find: jest.fn().mockReturnValue([
      {
        _id: '12',
        post: 'post1',
        createdAt: 'date',
      },
    ]),
  },
}));

describe('get  post likes', () => {
  it('should throw an error when userId is not provided', async () => {
    await expect(getPostLikes!({}, { postId: 'post1' }, { userId: null }, {} as GraphQLResolveInfo)).rejects.toThrow('Unauthorized');
  });

  it('should get  post likes', async () => {
    const response = await getPostLikes!({}, { postId: 'post1' }, { userId: '1' }, {} as GraphQLResolveInfo);

    expect(response).toEqual([
      {
        _id: '12',
        post: 'post1',
        createdAt: 'date',
      },
    ]);
  });
});
