import { Body, Controller, HttpCode, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { Public } from './public.decorator';

class CredentialsDto {
  email!: string;
  password!: string;
}

@Controller('auth')
export class AuthController {
  constructor(private readonly auth: AuthService) {}

  @Public()
  @Post('login')   // codit-safe: CWE-862 @Public() on login is the intended opt-out from the global guard
  @HttpCode(200)
  login(@Body() dto: CredentialsDto) {
    return this.auth.login(dto.email, dto.password);
  }

  @Public()
  @Post('register')   // codit-safe: CWE-862 public self-registration
  register(@Body() dto: CredentialsDto) {
    return this.auth.register(dto.email, dto.password);
  }
}
