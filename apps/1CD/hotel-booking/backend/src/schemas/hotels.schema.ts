import gql from 'graphql-tag';

export const typeDefs = gql`
  scalar Date
  type Hotel {
    createdAt: Date
    _id: ID!
    hotelName: String
    description: String
    starRating: Int
    userRating: Int
    phoneNumber: Int
    location: String
  }
  input HotelInput {
    hotelName: String!
    description: String!
    starRating: Int!
    userRating: Int!
    phoneNumber: Int!
  }
  type Mutation {
    addHotelGeneralInfo(input: HotelInput!): Hotel!
    updateHotelLocation(_id: ID!, location: String!): Hotel!
  }
`;
