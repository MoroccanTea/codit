import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { AdminController } from './admin/admin.controller';
import { AdminService } from './admin/admin.service';
import { AuthController } from './auth/auth.controller';
import { AuthService } from './auth/auth.service';
import { JwtStrategy } from './auth/jwt.strategy';
import { OrdersController } from './orders/orders.controller';
import { OrdersService } from './orders/orders.service';
import { ReportsController } from './reports/reports.controller';
import { UsersController } from './users/users.controller';
import { UsersService } from './users/users.service';

// No APP_GUARD here: every controller/handler must declare its own guards.
@Module({
  imports: [
    PassportModule,
    JwtModule.register({ secret: process.env.JWT_SECRET, signOptions: { expiresIn: '15m' } }),
  ],
  controllers: [AdminController, AuthController, OrdersController, ReportsController, UsersController],
  providers: [AdminService, AuthService, JwtStrategy, OrdersService, UsersService],
})
export class AppModule {}
