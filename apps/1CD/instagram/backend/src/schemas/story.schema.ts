// /* eslint-disable no-secrets/no-secrets */
// import gql from 'graphql-tag';

// export const typeDefs = gql`
//   type OneStory {
//     _id: ID!
//     image: String
//     description: String
//     createdAt: Date
//     endDate: String
//   }

//   type UserStory {
//     story: OneStory!
//   }

//   type Story {
//     _id: ID!
//     userId: ID!
//     userStories: [UserStory!]
//   }

//   type StoryInfo {
//     _id: ID!
//     userId: User!
//     userStories: [UserStory!]
//   }

//   input StoryInput {
//     userId: ID!
//     description: String
//     image: String
//   }

//   type Query {
//     getMyActiveStories: StoryInfo!
//   }

//   type Query {
//     getMyStory(_id: ID!): [StoryInfo!]
//   }

//   type Query {
//     getFollowingStories: [StoryInfo!]
//   }

//   type Query {
//     getMyStories: StoryInfo!
//   }

//   type Query {
//     getPublicAccStories(userId: ID!): [StoryInfo!]
//   }

//   type Mutation {
//     createStory(input: StoryInput!): Story!
//   }
// `;

import gql from 'graphql-tag';

export const typeDefs = gql`
  scalar Date

  type Story {
    _id: ID!
    image: String!
    createdAt: Date!
    endDate: String!
  }

  type UserStory {
    _id: ID!
    user: ID!
    stories: [Story!]!
  }

  type UserPopulatedStory {
    _id: ID!
    user: User!
    stories: [Story!]!
  }

  input StoryInput {
    user: ID!
    image: String!
  }

  type Query {
    getAllUsersWithLatestStories: [UserPopulatedStory!]! # For outer carousel
    getFollowingUserStories(user: ID!): UserPopulatedStory! # For inner carousel
    getFollowingStories: [UserStory!]
    getMyStory(_id: ID!): [UserStory!]
    getMyActiveStories: UserStory!
    getMyStories: UserStory!
  }

  type Mutation {
    createStory(input: StoryInput!): UserStory!
  }
`;
