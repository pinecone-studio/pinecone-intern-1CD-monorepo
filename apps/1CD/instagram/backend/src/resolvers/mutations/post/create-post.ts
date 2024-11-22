import { MutationResolvers } from '../../../generated';
import { PostModel } from '../../../models/post.model';

export const createPost: MutationResolvers['createPost'] = async (_, { user, description, images }) => {
  const createdPost = await PostModel.create({ user, description, images });

  return createdPost;
};
