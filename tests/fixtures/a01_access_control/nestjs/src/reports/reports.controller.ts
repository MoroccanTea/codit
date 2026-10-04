import { Controller, Get, Query, UseGuards } from '@nestjs/common';
import { HeaderRoleGuard } from '../auth/header-role.guard';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { ReportsService } from './reports.service';

@Controller('reports')
@UseGuards(JwtAuthGuard, HeaderRoleGuard)
export class ReportsController {
  constructor(private readonly reports: ReportsService) {}

  @Get('finance')
  finance(@Query('quarter') quarter: string) {
    return this.reports.financeSummary(quarter);
  }
}
