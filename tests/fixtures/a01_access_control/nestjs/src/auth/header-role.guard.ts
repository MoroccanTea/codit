import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';

/**
 * Used by the finance dashboard; the API gateway is supposed to inject X-Role.
 */
@Injectable()
export class HeaderRoleGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();
    return request.headers['x-role'] === 'finance';   // codit-expect: CWE-807 authorization based on a client-supplied X-Role header
  }
}
