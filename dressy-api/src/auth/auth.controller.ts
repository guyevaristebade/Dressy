import { Body, Controller, Post, Res } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register-dto';
import { Profile } from '@prisma/client';
import { LoginDto } from './dto/login-dto';
import { Response } from 'express';

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

  // TODO: Logout route
  // @Delete('logout')
  // async logout(@Res({ passthrough: true }) res: Response, req: Request) {}

  // TODO: Refresh token route

  /*
Je dois implémenter la route pour le logout 

Je dois revoir ce que GPT m'a montrer concernant le login et le refresh token

*/
}
