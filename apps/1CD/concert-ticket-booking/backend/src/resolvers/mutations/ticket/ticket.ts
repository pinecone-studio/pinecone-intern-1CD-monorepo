import { MutationResolvers } from '../../../generated';
import Ticket from '../../../models/ticket.model';

export const createTicket: MutationResolvers['createTicket'] = async (_, { input, scheduledDay }) => {
  const newTicket = await Ticket.create({
    scheduledDay: scheduledDay,
    ticketType: input,
  });

  return newTicket;
};
