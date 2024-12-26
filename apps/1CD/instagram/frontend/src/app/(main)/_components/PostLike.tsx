'use client';
import { useCreatePostLikeMutation, useDeletePostLikeMutation, useGetPostLikeQuery } from '@/generated';
import { Heart } from 'lucide-react';
import React from 'react';

export const PostLike = ({ id }: { id: string }) => {
  const [createPostLike] = useCreatePostLikeMutation();
  const [deletePostLike] = useDeletePostLikeMutation();
  const { data, refetch } = useGetPostLikeQuery({
    variables: {
      postId: id,
    },
  });

  const handleChangePostLike = async () => {
    if (!data?.getPostLike?.isLike) {
      await createPostLike({
        variables: {
          postId: id,
          isLike: true,
        },
      });
      await refetch();
    }
    if (data?.getPostLike?.isLike) {
      await deletePostLike({
        variables: {
          postLikeId: data?.getPostLike?._id,
        },
      });
      await refetch();
    }
  };

  return (
    <p className="cursor-pointer" onClick={handleChangePostLike} data-testid="LikeBtn">
      {data?.getPostLike?.isLike ? <Heart fill="111" /> : <Heart />}
    </p>
  );
};