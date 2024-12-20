'use client';
import { useAuth } from '@/components/providers/AuthProvider';
import { Button } from '@/components/ui/button';
import { useGetMyPostsQuery } from '@/generated';

import { Grid3x3, Save, Settings } from 'lucide-react';
import { useState } from 'react';
import ProImg from '@/components/user-profile/ChangeProImg';

const UserProfile = () => {
  const { user, changeProfileImg } = useAuth();
  const { data, error } = useGetMyPostsQuery();
  const [proImgData, setProImgData] = useState<string>('');

  return (
    <div className="my-10 mx-auto" data-cy="user-profile-page">
      <div className="w-[900px]">
        <div className="flex flex-row justify-evenly mb-10">
          <section>
            <ProImg changeProfileImg={changeProfileImg} proImgData={proImgData} setProImgData={setProImgData} _id={user?._id} prevProImg={user?.profileImg || ''} />
          </section>
          <div className="flex flex-col justify-between">
            <div className="flex flex-row items-center space-x-4">
              <h1 className="font-bold text-2xl" data-cy="username">
                {user?.userName}
              </h1>
              <Button className="text-black bg-gray-200 hover:bg-gray-300 h-8">Edit Profile</Button>
              <Button className="text-black bg-gray-200 hover:bg-gray-300 h-8">Add tools</Button>
              <div>
                <Settings />
              </div>
            </div>
            <div className="flex flex-row space-x-8">
              <div className="flex flex-row items-center space-x-2">
                <div className="font-semibold">
                  {/* {loading && <Skeleton className="h-4 w-10" />} */}
                  {error && (
                    <p className="font-normal" data-cy="postnumberError">
                      Something wrong
                    </p>
                  )}
                  <h1 className="font-normal" data-cy="postNumberDone">
                    {data?.getMyPosts.length}
                  </h1>
                </div>
                <p>posts</p>
              </div>
              <div className="flex flex-row space-x-2">
                <h1 className="font-semibold" data-cy="followerNumber">
                  {user?.followerCount}
                </h1>
                <p>followers</p>
              </div>
              <div className="flex flex-row space-x-2">
                <h1 className="font-semibold" data-cy="followingNumber">
                  {user?.followingCount}
                </h1>
                <p>following</p>
              </div>
            </div>
            <div>
              <h1 className="font-bold" data-cy="fullname">
                {user?.fullName}
              </h1>
              <p>{user?.bio}энэ хэсэг дээр био дэлгэрэнгүй байна</p>
            </div>
          </div>
        </div>
        <div className="border-t-4 border-t-gray-200 flex relative">
          <div className="text-gray-400 pt-4 flex flex-row space-x-1 items-center border-t-2 hover:border-t-black hover:text-black absolute -top-1 left-[40%]">
            <Grid3x3 />
            <p>POSTS</p>
          </div>
          <div className="text-gray-400 pt-4 flex flex-row space-x-1 items-center border-t-2 hover:border-t-black hover:text-black absolute -top-1 right-[40%]">
            <Save />
            <p>SAVED</p>
          </div>
        </div>
        <div className="mt-14">
          {/* {loading && <Skeleton className="h-[75vh] w-full" />} */}
          {error && (
            <p className="font-normal" data-cy="postsError">
              Something wrong
            </p>
          )}
          {/* {data?.getMyPosts.length === 0 && <NoPost />} */}
        </div>
      </div>
    </div>
  );
};
export default UserProfile;
