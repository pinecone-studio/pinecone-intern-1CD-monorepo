import jwt from 'jsonwebtoken';
import { Context } from 'src/types';

interface JwtPayload {
  role: string;
}

const verifyToken = (token: string): JwtPayload | null => {
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET as string);
    if (typeof decoded === 'object' && 'role' in decoded) {
      return decoded as JwtPayload;
    }
    return null;
  } catch (error) {
    console.error('Token verification failed:', error);
    return null;
  }
};

export const checkToken = (roles: string[], context: Context) => {
  const token = context.req.headers.get('authorization');

  if (!token) return false;

  const decoded = verifyToken(token);
  return roles.includes(decoded?.role as string) || false;
};
