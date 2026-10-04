import { Body, Controller, Patch, Req, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { User } from './user.entity';
import { UsersService } from './users.service';

class UpdateProfileDto {
  displayName?: string;
  bio?: string;
}

@Controller('users')
@UseGuards(JwtAuthGuard)
export class UsersController {
  constructor(private readonly users: UsersService) {}

  @Patch('me')
  updateMe(@Req() req: { user: { id: string } }, @Body() body: Partial<User>) {
    return this.users.update(req.user.id, body);   // codit-expect: CWE-915 raw Partial<User> body (roles, isAdmin, twoFactorEnabled) persisted as-is
  }

  @Patch('me/profile')
  updateProfile(@Req() req: { user: { id: string } }, @Body() dto: UpdateProfileDto) {
    return this.users.update(req.user.id, { displayName: dto.displayName, bio: dto.bio });   // codit-safe: CWE-915 explicit field mapping from a narrow DTO
  }
}
