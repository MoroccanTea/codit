import { Controller, Delete, Get, HttpCode, Param, Post, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Roles } from '../auth/roles.decorator';
import { RolesGuard } from '../auth/roles.guard';
import { AdminService } from './admin.service';

@Controller('admin')
@UseGuards(AuthGuard('jwt'), RolesGuard)
@Roles('admin')
export class AdminController {
  constructor(private readonly admin: AdminService) {}

  @Get('users')   // codit-safe: CWE-862 class-level @UseGuards(AuthGuard('jwt'), RolesGuard) + @Roles('admin')
  listUsers() {
    return this.admin.listUsers();
  }

  @Delete('users/:id')   // codit-safe: CWE-862,CWE-639 class-level guards apply; admins manage any account
  @HttpCode(204)
  removeUser(@Param('id') id: string) {
    return this.admin.removeUser(id);
  }

  @Post('cache/flush')   // codit-safe: CWE-862 class-level guards apply
  flush() {
    return this.admin.flushCaches();
  }
}
