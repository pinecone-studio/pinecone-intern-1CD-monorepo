import { MutationResolvers } from '../../../generated';
import Event from '../../../models/event.model';

export const deleteEvent: MutationResolvers['deleteEvent'] = async (_, { _id }) => {
  try {
    const eventDeleted = await Event.findOneAndDelete({ _id });
    if (!eventDeleted) {
      throw new Error('Event not found');
    }
    return {
      message: 'success',
    };
  } catch (e) {
    console.log({ e });
    return {
      message: 'error found',
    };
  }
};
