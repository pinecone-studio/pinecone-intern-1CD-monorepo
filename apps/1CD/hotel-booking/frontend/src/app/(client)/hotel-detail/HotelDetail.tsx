"use client";

import { PhoneCall } from "lucide-react";
import HotelRooms from "./HotelRooms";
import { useGetHotelQuery } from "@/generated";
import Image from "next/image";
import HotelImportant from "@/components/HotelImportant";
import HotelPolicies from "@/components/HotelPolicies";

const HotelDetail = () => {
    const { data, loading } = useGetHotelQuery({
        variables: {
            id: "674bfbd6a111c70660b55541"
        }
    });

    if (loading) return (<div>loading...</div>)
    return (
        <div data-cy="Hotel-Detail-Page" className="container mx-auto items-center flex flex-col gap-8">
            {data?.getHotel.images?.length &&
                data?.getHotel?.images?.length > 0 && <div data-cy="Hotel-Detail-Room-Image" className="max-w-[1160px] w-full flex gap-1">
                    <div className="flex-1">{<Image src={`${data?.getHotel.images[0]}`} alt="hotel image" width={580} height={433} className="w-full object-cover h-full" />}</div>

                    <div className="flex-1 flex flex-col gap-1">
                        <div className="flex-1 flex gap-1">
                            <Image src={`${data?.getHotel.images[0]}`} alt="hotel image" width={286} height={214} className="flex-1" />
                            <Image src={`${data?.getHotel.images[0]}`} alt="hotel image" width={286} height={214} className="flex-1" />
                        </div>
                        <div className="flex gap-1 flex-1">
                            <Image src={`${data?.getHotel.images[0]}`} alt="hotel image" width={286} height={214} className="flex-1" />
                            <Image src={`${data?.getHotel.images[0]}`} alt="hotel image" width={286} height={214} className="flex-1" />
                        </div>
                    </div>
                </div>
            }
            <div className="px-10 flex flex-col items-center max-w-[1160px] gap-14">
                <div className="flex gap-14">
                    <div className="flex-1 flex flex-col gap-2">
                        <div className="flex flex-col gap-6">
                            <div>
                                <div className="text-3xl font-semibold">{data?.getHotel.hotelName}</div>
                                <div className="text-base font-normal">{data?.getHotel.description}</div>
                            </div>
                            <div>excelent</div>
                        </div>
                        <div className="w-full border border-solid 1px bg-[#E4E4E7]"></div>
                        <div>
                            <div>Most popular facilities</div>
                            <div>Service</div>
                        </div>
                    </div>
                    <div className="flex-1 flex flex-col gap-2">
                        <div className="text-base font-bold">Location</div>
                        <div className="border border-solid 1px p-4">
                            <div>Damdinbazar street-52, Bayangol district, Bayangol, 212513 Ulaanbaatar, Mongolia</div>
                        </div>
                        <div>
                            <div className="text-base font-bold">Contact</div>
                            <div className="flex gap-3 items-center">
                                <PhoneCall className="w-5 h-5" />
                                <div>
                                    <p className="text-sm font-medium text-[#71717A]">phonenumber</p>
                                    <div>{data?.getHotel.phoneNumber}
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <HotelRooms />
                <div className="flex flex-col gap-20">
                    <HotelPolicies />
                    <div className="w-full border border-solid 1px bg-[#E4E4E7]"></div>
                    <HotelImportant />
                    <div className="w-full border border-solid 1px bg-[#E4E4E7]"></div>
                </div>
            </div>
        </div>
    )
}
export default HotelDetail;