import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { RegisterDto } from './dto/register-dto';
import { PrismaService } from 'src/prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import { Profile } from '@prisma/client';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}

  async createUser(registerDTO: RegisterDto): Promise<Profile> {
    const { email, fullName, password, profileName } = registerDTO;
    const existingUser = await this.prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      throw new HttpException('User already exists', HttpStatus.BAD_REQUEST, {
        cause: new Error('User already exists'),
      });
    }
    const salt = await bcrypt.genSalt(12);
    const hashPassword = await bcrypt.hash(password, salt);

    try {
      // Transaction séquentielle
      const profile = await this.prisma.$transaction(async (tx) => {
        const user = await tx.user.create({
          data: {
            email,
            password: hashPassword,
          },
        });
        return await tx.profile.create({
          data: {
            fullName,
            profileName,
            userId: user.id,
          },
        });
      });

      return profile;
    } catch (error) {
      if (error instanceof HttpException) throw error;

      throw new HttpException(
        'Internal server error',
        HttpStatus.INTERNAL_SERVER_ERROR,
        { cause: error },
      );
    }
  }
}
