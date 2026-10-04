import { Controller, Delete, Get, Param, Post, Req, UseGuards } from '@nestjs/common';
import { Request } from 'express';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { Roles } from '../auth/roles.decorator';
import { RolesGuard } from '../auth/roles.guard';
import { OrdersService } from './orders.service';

interface AuthenticatedRequest extends Request {
  user: { id: string; roles: string[] };
}

@Controller('orders')
export class OrdersController {
  constructor(private readonly orders: OrdersService) {}

  @UseGuards(JwtAuthGuard)
  @Get()   // codit-safe: CWE-862 method-level @UseGuards(JwtAuthGuard)
  list(@Req() req: AuthenticatedRequest) {
    return this.orders.listForUser(req.user.id);
  }

  @UseGuards(JwtAuthGuard)
  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.orders.findById(id);   // codit-expect: CWE-639 any order by id; the authenticated user is never compared to the owner
  }

  @UseGuards(JwtAuthGuard)
  @Get(':id/invoice')
  invoice(@Param('id') id: string, @Req() req: AuthenticatedRequest) {
    return this.orders.findOneForUser(id, req.user.id);   // codit-safe: CWE-639 lookup scoped to the authenticated user
  }

  @Delete(':id')   // codit-expect: CWE-862 the only handler of this controller without @UseGuards
  remove(@Param('id') id: string) {
    return this.orders.remove(id);
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('admin')
  @Post(':id/refund')   // codit-safe: CWE-862 method-level JwtAuthGuard + RolesGuard + @Roles('admin')
  refund(@Param('id') id: string) {
    return this.orders.refund(id);
  }
}
