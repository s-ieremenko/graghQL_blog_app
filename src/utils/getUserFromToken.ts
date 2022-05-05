import JWT from 'jsonwebtoken';
import { JWT_SIGNATURE } from '../key';

export const getUserFromToken = (token: string) => {
  try {
    return JWT.verify(token, JWT_SIGNATURE) as {
      userId: number
    };
  } catch (error) {
    return null;
  }
};