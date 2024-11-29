import gql from 'graphql-tag';

export const typeDefs = gql`
  scalar Date
  type User {
    _id: ID!
    name: String!
    email: String!
    bio: String!
    age: Int!
    gender: String!
    interests: [String!]
    photos: [String!]
    profession: String!
    schoolWork: [String!]
    createdAt: Date!
    updatedAt: Date!
  }

  input RegisterEmailInput {
    email: String!
  }

  input VerifyOtpInput {
    email: String!
    otp: Int!
  }
  input createPasswordInput {
    email: String!
    otp: Int!
    password: String!
  }
  type RegisterEmailResponse {
    email: String!
  }

  type VerifyingOtpResponse {
    email: String!
    otp: Int!
  }

  type Mutation {
    registerEmail(input: RegisterEmailInput!): RegisterEmailResponse!
    verifyOtp(input: VerifyOtpInput!): VerifyingOtpResponse!
  }
`;
