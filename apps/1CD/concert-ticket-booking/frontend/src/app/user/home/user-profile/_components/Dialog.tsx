import { useFormik } from 'formik';
import * as Yup from 'yup';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Order, useCancelTicketMutation } from '@/generated';
import { calculateTotalAmount } from '@/utils/calculate';
import { toast } from 'sonner';

const DialogComponent = ({ open, onClose, order, refetch }: { open: boolean; onClose: () => void; order: Order; refetch: () => void }) => {
  const orderId = order._id;
  const eventId = order.eventId;
  const totalAmount = calculateTotalAmount(order.ticketType);

  const [createRequest, { loading }] = useCancelTicketMutation({
    onCompleted: () => {
      refetch();
      toast.success('Successfully sent cancel request. Wait for admin to approve');
    },
    onError: (error) => {
      toast.error(error.message);
    },
  });

  const validationSchema = Yup.object({
    bank: Yup.string().required('Банк сонгоно уу'),
    accountNumber: Yup.string()
      .matches(/^[0-9]+$/, 'Зөвхөн тоо оруулна уу')
      .min(8)
      .max(16)
      .required('Дансны дугаарыг оруулна уу'),
    phoneNumber: Yup.string()
      .matches(/^[0-9]{8}$/, '8 оронтой утасны дугаар оруулна уу')
      .required('Утасны дугаарыг оруулна уу'),
    ownerName: Yup.string().min(2, 'Эзэмшигчийн нэр нь хамгийн багадаа 2 үсэгтэй байна').required('Эзэмшигчийн нэрийг оруулна уу'),
  });

  const formik = useFormik({
    initialValues: {
      bank: '',
      accountNumber: '',
      phoneNumber: '',
      ownerName: '',
    },
    validationSchema,
    onSubmit: async (values) => {
      await handleSubmit(values);
    },
  });

  const handleSubmit = async (values: typeof formik.values) => {
    await createRequest({
      variables: {
        input: {
          orderId,
          bankDatas: {
            bankName: values.bank,
            bankAccount: values.accountNumber,
            accountOwner: values.ownerName,
            phoneNumber: values.phoneNumber,
            eventId: eventId,
            totalPrice: totalAmount,
          },
        },
      },
    });
    onClose();
  };

  const renderInputField = (label: string, field: keyof typeof formik.values, placeholder: string, type = 'text') => (
    <div className="w-full flex items-baseline justify-end gap-2" data-cy={`input-${field}`}>
      <div>{label}</div>
      <div>
        <Input type={type} placeholder={placeholder} className="w-[318px]" {...formik.getFieldProps(field)} />
        {formik.touched[field] && formik.errors[field] && <div className="text-red-500 text-xs mt-1">{formik.errors[field]}</div>}
      </div>
    </div>
  );

  return (
    <Dialog open={open} data-cy="dialog-component">
      <DialogContent onClose={onClose} data-cy="dialog-content">
        <DialogHeader data-cy="dialog-header">
          <DialogTitle data-cy="dialog-title">Тасалбар цуцлах</DialogTitle>
          <DialogDescription data-cy="dialog-description">{order._id} тасалбараа цуцлахдаа итгэлтэй байна уу?</DialogDescription>
        </DialogHeader>

        <form onSubmit={formik.handleSubmit} className="flex flex-col gap-4">
          <div className="w-full flex items-baseline justify-end gap-2" data-cy="select-bank">
            <div className="text-right">Банк</div>
            <Select data-cy="bank-select" value={formik.values.bank} onValueChange={(val) => formik.setFieldValue('bank', val)}>
              <SelectTrigger className="w-[318px]" data-cy="bank-select-trigger">
                <SelectValue placeholder="Сонгох" data-cy="bank-select-value" />
              </SelectTrigger>
              <SelectContent className="w-full" data-cy="bank-select-content">
                <SelectItem value="golomt" data-cy="select-item-golomt">
                  Голомт
                </SelectItem>
                <SelectItem value="khaan" data-cy="select-item-khaan">
                  Хаан
                </SelectItem>
                <SelectItem value="tdb" data-cy="select-item-tdb">
                  TDB
                </SelectItem>
              </SelectContent>
            </Select>
            {formik.touched.bank && formik.errors.bank && <div className="text-red-500 text-sm mt-1">{formik.errors.bank}</div>}
          </div>

          {renderInputField('Дансны №', 'accountNumber', 'Дансны дугаар')}
          {renderInputField('Утасны №', 'phoneNumber', 'Утасны дугаар')}
          {renderInputField('Нэр', 'ownerName', 'Эзэмшигчийн нэр')}

          <DialogFooter data-cy="dialog-footer">
            <Button type="submit" data-cy="submit-cancel-request" disabled={loading || !formik.isValid || !formik.dirty}>
              Цуцлах хүсэлт илгээх
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
};

export default DialogComponent;
