import { Controller, Get, HttpCode, Post } from '@nestjs/common';
import { Public } from '../auth/public.decorator';
import { Roles } from '../auth/roles.decorator';
import { AdminService } from './admin.service';

@Controller('admin')
export class AdminController {
  constructor(private readonly admin: AdminService) {}

  @Roles('admin')
  @Get('stats')   // codit-safe: CWE-862 global guards + @Roles('admin')
  stats() {
    return this.admin.stats();
  }

  // Needed by the BI tool, which cannot send a bearer token.
  @Public()   // codit-expect: CWE-862 @Public() on a full user export bypasses the global JwtAuthGuard
  @Get('users/export')
  exportUsers() {
    return this.admin.exportAllUsers();
  }

  @Public()   // codit-expect: CWE-862 @Public() on a state-changing admin action
  @Post('reindex')
  @HttpCode(202)
  reindex() {
    return this.admin.rebuildSearchIndex();
  }
}
