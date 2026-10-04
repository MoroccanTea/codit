import { Controller, Get } from '@nestjs/common';
import { Public } from '../auth/public.decorator';

@Controller('health')
export class HealthController {
  @Public()
  @Get()   // codit-safe: CWE-862 public liveness probe, returns no data
  check() {
    return { status: 'ok' };
  }
}
