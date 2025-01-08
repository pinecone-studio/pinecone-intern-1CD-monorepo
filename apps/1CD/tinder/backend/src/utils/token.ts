
import { NextRequest } from 'next/server';
import { giveTokenIndev } from './for-dev-token';
import { checkTokenInProd } from './for-prod-token';
export const getUserId = (req: NextRequest) => {
  const tokenForDev=giveTokenIndev();
  const tokenForProd=checkTokenInProd({ req }); 
  return tokenForDev || tokenForProd;
};
