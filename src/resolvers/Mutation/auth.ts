import { Context } from '../../index';
import validator from 'validator';
import bcrypt from 'bcryptjs';
import JWT from 'jsonwebtoken';
import { JWT_SIGNATURE } from '../../key';

interface SignUpArgs {
  credentials: {
    email: string;
    password: string
  };
  name: string;
  bio: string;
}

interface SignInArgs {
  credentials: {
    email: string;
    password: string
  };
}

interface UserPayload {
  userErrors: {
    message: string
  }[],
  token: string | null
}

export const authResolvers = {
  signup: async (_: any, { credentials, name, bio }: SignUpArgs, { prisma }: Context): Promise<UserPayload> => {

    const { email, password } = credentials;
    const isEmail = validator.isEmail(email);

    if (!isEmail) {
      return {
        userErrors: [
          {
            message: 'Invalid email'
          }
        ],
        token: null
      };
    }

    const isValidPassword = validator.isStrongPassword(password, {
      minLength: 8, minNumbers: 1, minUppercase: 1, minSymbols: 1, minLowercase: 1
    });
    if (!isValidPassword) {
      return {
        userErrors: [
          {
            message: 'The password should have min length of 8 and contain at least one number, one special symbol, one uppercase letter and one lowercase letter'
          }
        ],
        token: null
      };
    }
    if (!name || !bio) {
      return {
        userErrors: [
          {
            message: 'Invalid name or bio'
          }
        ],
        token: null
      };
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await prisma.user.create({
      data: {
        email,
        name,
        password: hashedPassword
      }
    });

    await prisma.profile.create({
      data: {
        bio,
        userId: user.id
      }
    });

    const token = await JWT.sign({
      userId: user.id
    }, JWT_SIGNATURE, { expiresIn: 230000 });
    return {
      userErrors: [],
      token
    };
  },
  signin: async (_: any, { credentials }: SignInArgs, { prisma }: Context): Promise<UserPayload> => {
    const { email, password } = credentials;
    const user = await prisma.user.findUnique({
      where: {
        email
      }
    });

    if (!user) {
      return {
        userErrors: [
          { message: 'Invalid credentials' }
        ],
        token: null
      };
    }
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return {
        userErrors: [{ message: 'Invalid credentials' }],
        token: null
      };
    }

    return {
      userErrors: [],
      token: JWT.sign({ userId: user.id }, JWT_SIGNATURE, {
        expiresIn: 2300000
      })
    };
  }

};
