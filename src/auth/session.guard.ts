import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { AuthService } from './auth.service';

@Injectable()
export class SessionGuard implements CanActivate {
  constructor(private readonly authService: AuthService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const userAgent = request.headers['user-agent'];
    const ipAddress = request.ip;
    const bearer = request.headers.authorization;
    const accessToken = bearer.replace('Bearer ', '');

    if (accessToken) {
      await this.authService.updateLastOnline(
        accessToken,
        userAgent,
        ipAddress,
      );
    }

    return true;
  }
}
