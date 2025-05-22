import {
  Body,
  Controller,
  Delete,
  Post,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register-dto';
import { Profile } from '@prisma/client';
import { LoginDto } from './dto/login-dto';
import { Response, Request } from 'express';
import { JwtAuthGuard } from './guards/jwt-auth.guard';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  async register(@Body() body: RegisterDto): Promise<Profile> {
    return this.authService.createUser(body);
  }

  @Post('login')
  async login(
    @Body() dto: LoginDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    return this.authService.login(dto, res);
  }

  // TODO: Logout route with guard

  @UseGuards(JwtAuthGuard)
  @Delete('logout')
  logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const user = (req as any).user as { userId: string; role: string };
    return this.authService.logout(user.userId, res);
  }

  // TODO: Refresh token route
}
