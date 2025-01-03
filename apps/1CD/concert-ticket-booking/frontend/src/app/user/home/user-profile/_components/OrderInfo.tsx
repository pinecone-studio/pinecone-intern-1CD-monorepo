import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Order, useGetOrderQuery } from '@/generated';
import dayjs from 'dayjs';
import { Clock } from 'lucide-react';
import { useState } from 'react';
import DialogComponent from './Dialog';
import { isLessThan24Hours } from '@/utils/to-check';
import { calculateTotalAmount } from '@/utils/calculate';

const OrderInfo = () => {
  const { data, refetch } = useGetOrderQuery();
  const orders = data?.getOrder;
  const [open, setOpen] = useState(false);

  const onClose = () => {
    setOpen(false);
  };

  return (
    <div className="text-white w-[841px]" data-cy="order-info-container">
      <h1 data-cy="order-info-title" className="text-2xl font-semibold mb-6">
        Захиалгын мэдээлэл
      </h1>
      {orders?.map((order) => (
        <Card className="bg-[#131313] border-none px-8 pt-8 pb-6 mb-8" key={order?._id} data-cy={`order-card-${order?._id}`}>
          <div className="text-white flex justify-between items-center mb-4">
            <div className="flex gap-1">
              <h2 data-cy={`order-id-${order?._id}`} className="text-base font-normal text-muted-foreground">
                Захиалгын дугаар :{' '}
              </h2>
              {order?._id}
              <p className="flex items-center gap-2 ml-[14px]">
                <Clock className="h-4 w-4 " /> {dayjs(order?.createdAt).format('YYYY.MM.DD')}
              </p>
            </div>

            {order?.status === 'pending' && (
              <div data-cy={`order-status-pending-${order?._id}`}>
                <span className="text-base font-normal text-muted-foreground"> Төлөв: </span>
                <span className="rounded-full bg-black py-[2px] px-[10px] border-[1px] border-[#27272A] text-xs font-semibold">Цуцлах хүсэлт илгээсэн</span>
              </div>
            )}
            {isLessThan24Hours(order?.createdAt) && order?.status !== 'pending' && (
              <>
                <Button className="bg-[#27272A]" onClick={() => setOpen(true)} data-cy={`cancel-button-${order?._id}`}>
                  Цуцлах
                </Button>
                <DialogComponent open={open} onClose={onClose} order={order as Order} refetch={refetch} />
              </>
            )}
          </div>
          {order?.ticketType.map((ticket, index) => (
            <div
              className="py-4 px-6 rounded-[6px] h-[52px] bg-[#131313] border-dashed border-[1px] border-muted-foreground mb-2 flex justify-between items-center"
              key={ticket._id}
              data-cy={`ticket-card-${ticket._id}`}
            >
              <div>
                <span className={`${index == 0 ? 'text-[#4651C9]' : index == 1 ? 'text-[#C772C4]' : 'text-white'} flex gap-2 items-center font-bold text-sm`} data-cy={`ticket-zone-${ticket._id}`}>
                  <div className={`${index == 0 ? 'bg-[#4651C9]' : index == 1 ? 'bg-[#C772C4]' : 'bg-white'} h-3 w-3 rounded-full`}></div>
                  {ticket.zoneName}
                </span>
              </div>
              <span className="text-white flex gap-2 items-center" data-cy={`ticket-price-${ticket._id}`}>
                <span className="text-base font-normal text-muted-foreground">
                  {ticket.unitPrice}₮×{ticket.soldQuantity}
                </span>
                {Number(ticket.unitPrice) * Number(ticket.soldQuantity)}₮
              </span>
            </div>
          ))}
          <div className="py-4 px-6 text-white flex items-center justify-between" data-cy={`order-total-${order?._id}`}>
            <span className="font-light text-sm">Төлсөн дүн</span>
            {order?.ticketType && <span className="font-bold text-xl">{calculateTotalAmount(order?.ticketType)}₮</span>}
          </div>
        </Card>
      ))}
    </div>
  );
};

export default OrderInfo;
