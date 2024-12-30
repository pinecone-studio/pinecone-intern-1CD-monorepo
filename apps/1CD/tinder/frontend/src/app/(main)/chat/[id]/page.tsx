'use client';

import { useLoadingstates } from '@/hooks/use-loading-states';
import { Chatpart } from '@/components/Chatpart';
import { Chatsidebar } from '@/components/Chatsidebar';
import { Loader } from '@/components/Loader';
import { Matches } from '@/components/Matches';
import { CREATE_CHAT } from '@/graphql/chatgraphql';
import { useMutation } from '@apollo/client';
import { useParams } from 'next/navigation';
import { ChangeEvent, useState } from 'react';

const Chat = ({ authToken }: any) => {
  const [message, setMessage] = useState<string>('');
  const params = useParams<{ id: string }>();
  const { id } = params;
  const user2 = id;
  const [createChat] = useMutation(CREATE_CHAT);

  const { chatloading, response, pageloading, errormessage,matchedData, refetchmatch, refetch, loading} = useLoadingstates(user2)
  const handleMessageChange = (e: ChangeEvent<HTMLInputElement>) => {
    setMessage(e.target.value);
  };
  const sendMessage = async () => {
      await createChat({
        variables: {
          input: {
            content: message,
            user2: user2,
          },
        },
      });
      setMessage('');
      refetch();
      refetchmatch();
  };
  if (pageloading) {
    return (
      <div className="flex items-center justify-center h-screen">
        <Loader />
      </div>
    );
  }
  if (matchedData) {
    return (
      <div className="max-w-[1000px] m-auto h-screen flex flex-col" data-cy="Chat-Matches-Part">
        <Matches />
        <div className="flex flex-1">
          <Chatsidebar />
          <Chatpart
            chatloading={chatloading}
            response={response}
            errormessage={errormessage}
            loading={loading}
            handleMessageChange={handleMessageChange}
            sendMessage={sendMessage}
            message={message}
            authToken={authToken}
          />
        </div>
      </div>
    );
  }
  
  <div className="flex flex-col items-center justify-center h-screen" data-cy="Error occured">
      <p>Error occurred, try again</p>
  </div>
};
export default Chat;
