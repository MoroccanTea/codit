import { Body, Controller, Delete, Get, Param, Post, Req } from '@nestjs/common';
import { Roles } from '../auth/roles.decorator';
import { ProjectsService } from './projects.service';

class CreateProjectDto {
  name!: string;
  description?: string;
}

// No @UseGuards on purpose: APP_GUARD (JwtAuthGuard + RolesGuard) is registered in AppModule.
@Controller('projects')
export class ProjectsController {
  constructor(private readonly projects: ProjectsService) {}

  @Get()   // codit-safe: CWE-862 global APP_GUARD JwtAuthGuard protects every route
  list(@Req() req: { user: { id: string } }) {
    return this.projects.listForUser(req.user.id);
  }

  @Post()   // codit-safe: CWE-862 global APP_GUARD JwtAuthGuard
  create(@Req() req: { user: { id: string } }, @Body() dto: CreateProjectDto) {
    return this.projects.create(req.user.id, { name: dto.name, description: dto.description });
  }

  @Roles('admin')
  @Delete(':id')   // codit-safe: CWE-862,CWE-639 global JwtAuthGuard + RolesGuard with @Roles('admin')
  remove(@Param('id') id: string) {
    return this.projects.archive(id);
  }
}
