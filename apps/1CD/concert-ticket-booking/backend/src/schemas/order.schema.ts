import gql from 'graphql-tag';

export const typeDefs = gql`

type Order {
    _id:ID!
    userId:User!
    eventId: ID!
    ticketId: ID!
    status:String!
    orderNumber:Int!
    ticketType: [TicketType!]!
    createdAt:Date!
    updatedAt:Date!
}
input OrderInput {
    eventId:ID!
    ticketId:ID!
    status:String!
    orderNumber:Int!
    ticketType:[MyTicketTypeInput!]!
}
input MyTicketTypeInput {
    _id:ID!
    zoneName: String!
    soldQuantity: Int!
    totalQuantity:Int!
    unitPrice: Int!
    discount: Int!
    additional: String!
  }
  input ChangeStatusInput {
        orderId:ID!
        requestId:ID!
}

type Query {
    getOrder: [Order]!
}
type ChangeStatusResponse {
  message:String!
}

type Mutation {
    changeStatus(input: ChangeStatusInput!): ChangeStatusResponse!
    addToCarts(input: OrderInput!): Order!
    deleteOrder(_id: ID!): Order!
}
`