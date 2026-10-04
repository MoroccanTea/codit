import { Body, Controller, HttpCode, Post, Req, UseGuards } from '@nestjs/common';
import { Public } from './public.decorator';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './jwt-auth.guard';

class LoginDto {
  email!: string;
  password!: string;
}

@Controller('auth')
export class AuthController {
  constructor(private readonly auth: AuthService) {}

  @Public()
  @Post('login')   // codit-safe: CWE-862 login is intentionally public (@Public marker)
  @HttpCode(200)
  login(@Body() dto: LoginDto) {
    return this.auth.login(dto.email, dto.password);
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout')   // codit-safe: CWE-862 method-level JwtAuthGuard
  @HttpCode(204)
  logout(@Req() req: { user: { id: string } }) {
    return this.auth.revokeSessions(req.user.id);
  }
}
