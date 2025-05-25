import {
  ForbiddenException,
  HttpException,
  HttpStatus,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { RegisterDto } from './dto/register-dto';
import { PrismaService } from 'src/prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import { Profile } from '@prisma/client';
import { JwtService } from '@nestjs/jwt';
import { LoginDto } from './dto/login-dto';
import { Response } from 'express';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
  ) {}

  async logout(userId: string, res: Response) {
    await this.prisma.user.update({
      where: { id: userId },
      data: { refreshToken: null },
    });

    res.clearCookie('access_token');
    res.clearCookie('refresh_token');
    return { message: 'Logout successful' };
  }

  async login(loginDTO: LoginDto, res: Response) {
    const { email, password } = loginDTO;
    const user = await this.prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      throw new HttpException('Invalid credentials', HttpStatus.UNAUTHORIZED);
    }

    const isPasswordValid = await bcrypt.compare(password, user.password ?? '');
    if (!isPasswordValid)
      throw new UnauthorizedException('username or password invalid');

    const tokens = await this.generateTokens(user.id);
    await this.updateRefreshToken(user.id, tokens.refreshToken);

    res.cookie('access_token', tokens.accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 15 * 60 * 1000,
    });

    res.cookie('refresh_token', tokens.refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return tokens;
  }

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

  async generateTokens(userId: string) {
    const payload = { sub: userId };

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(payload, {
        secret: process.env.JWT_ACCESS_SECRET,
        expiresIn: '15m',
      }),

      this.jwtService.signAsync(payload, {
        secret: process.env.JWT_REFRESH_SECRET,
        expiresIn: '7d',
      }),
    ]);

    return { accessToken, refreshToken };
  }

  async updateRefreshToken(userId: string, refreshToken: string) {
    const hashedToken = await bcrypt.hash(refreshToken, 10);
    await this.prisma.user.update({
      where: { id: userId },
      data: { refreshToken: hashedToken },
    });
  }

  async verifyToken(token: string, secret: string): Promise<any> {
    return this.jwtService.verifyAsync(token, { secret });
  }

  async refreshTokenRotation(refreshTokenCookie: string, userId: string) {
    try {
      const user = await this.prisma.user.findUnique({
        where: { id: userId },
        select: { refreshToken: true },
      });

      if (!user || !user.refreshToken)
        throw new UnauthorizedException('Missing refresh token');

      const isRefreshTokenValid = await bcrypt.compare(
        refreshTokenCookie,
        user.refreshToken,
      );

      if (!isRefreshTokenValid) {
        // invalidate the refresh token in the database
        // caused by usation of old refresh token
        await this.prisma.user.update({
          where: { id: userId },
          data: { refreshToken: null },
        });
        throw new UnauthorizedException('Invalid refresh token');
      }

      const tokens = await this.generateTokens(userId);
      await this.updateRefreshToken(userId, tokens.refreshToken);
      return tokens;
    } catch (error) {
      throw new HttpException(
        'Internal server error',
        HttpStatus.INTERNAL_SERVER_ERROR,
        { cause: error },
      );
    }
  }
}
