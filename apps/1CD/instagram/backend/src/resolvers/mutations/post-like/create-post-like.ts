import { MutationResolvers } from '../../../generated';
import { PostLikeModel } from '../../../models';

export const createPostLike: MutationResolvers['createPostLike'] = async (_, { postId, isLike }, { userId }) => {
  if (!userId) throw new Error('Unauthorized');
  if (!isLike) throw new Error('Error create postlike');
  const createdPostLike = await PostLikeModel.create({ user: userId, post: postId, isLike });

  return createdPostLike;
};