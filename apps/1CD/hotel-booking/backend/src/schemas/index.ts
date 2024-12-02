import { mergeTypeDefs } from '@graphql-tools/merge';
import { typeDefs as CommonTypeDefs } from './common.schema';
import { typeDefs as HotelsTypeDefs } from './hotels.schema';

import { typeDefs as RoomTypeDefs } from './room.schema';
import { typeDefs as UserTypeDefs } from './user.schema';

export const typeDefs = mergeTypeDefs([CommonTypeDefs, HotelsTypeDefs, RoomTypeDefs, UserTypeDefs]);

