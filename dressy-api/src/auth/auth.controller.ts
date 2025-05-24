import {
  Body,
  Controller,
  Delete,
  Get,
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
// import { Roles } from './decorators/roles.decorator';
// import { RolesGuard } from './guards/role.guard';

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
  @Get('refresh')
  async refresh(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const user = (req as any).user as { userId: string };
    console.log('User:', user);
    const refresh_token = req.cookies['refresh_token'];
    return this.authService.refreshTokenRotation(refresh_token, user.userId);
  }

  // TODO: Refresh token route
  @UseGuards(JwtAuthGuard)
  @Get('test')
  test() {
    return { message: 'Test route' };
  }

  @UseGuards(JwtAuthGuard)
  @Delete('logout')
  logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const user = (req as any).user as { userId: string };
    return this.authService.logout(user.userId, res);
  }
}
