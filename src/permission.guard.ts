import {
  CanActivate,
  ExecutionContext,
  Inject,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Request } from 'express';
import { Observable } from 'rxjs';
import { Permission } from './user/entities/permission.entity';

interface JwtUserData {
  userId: number;
  username: string;
  roles: string[];
  permissions: Permission[];
}

declare module 'express' {
  interface Request {
    user: JwtUserData;
  }
}

@Injectable()
export class PermissionGuard implements CanActivate {
  @Inject()
  private reflector: Reflector;

  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const request: Request = context.switchToHttp().getRequest();

    if (!request.user) return true;

    const permissions = request.user.permissions;

    const requestPermission = this.reflector.getAllAndOverride<string[]>(
      'require-permission',
      [context.getClass(), context.getHandler()],
    );

    if (!requestPermission) return true;

    for (let index = 0; index < requestPermission.length; index++) {
      const currentPermission = requestPermission[index];
      const found = permissions.find((item) => item.code === currentPermission);

      if (!found) throw new UnauthorizedException('权限不足');
    }

    return true;
  }
}
