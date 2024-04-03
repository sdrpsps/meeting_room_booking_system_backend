import {
  ExecutionContext,
  SetMetadata,
  createParamDecorator,
} from '@nestjs/common';
import { Request } from 'express';

// 要求登录装饰器
export const RequireLogin = () => SetMetadata('require-login', true);

// 要求权限装饰器
export const RequirePermission = (...permissions: string[]) =>
  SetMetadata('require-permission', permissions);

// 提取用户信息装饰器
export const UserInfo = createParamDecorator(
  (data: string, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest<Request>();

    if (!request.user) return null;

    return data ? request.user[data] : request.user;
  },
);
