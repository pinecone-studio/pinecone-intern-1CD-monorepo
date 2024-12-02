import { AccountVisibility, FollowStatus, MutationResolvers } from '../../../generated';
import { followModel } from '../../../models/follow.model';
import { userModel } from '../../../models/user.model';

export const sendFollowReq: MutationResolvers['sendFollowReq'] = async (_: unknown, { followerId, followingId }) => {
  const user = await userModel.findById(followingId);

  if (!user) throw new Error('User not found');

  const { accountVisibility } = user;

  const status = accountVisibility === AccountVisibility.Private ? FollowStatus.Pending : FollowStatus.Approved;

  const sendRequest = await followModel.create({ followerId, followingId, status });

  return sendRequest;
};