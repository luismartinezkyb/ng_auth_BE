import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { AuthService } from '../auth.service';

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    private jwtService: JwtService,
    private authService: AuthService,
  ) {}
  async canActivate(context: ExecutionContext): Promise<boolean> {
    try {
      const request = context.switchToHttp().getRequest();
      const token = this.extractTokenFromHeader(request);
      // console.log(token);
      if (!token) {
        throw new UnauthorizedException('NEED_TOKEN');
      }
      //CAMBIAR EL JWT SEED POR UNA VARIABLE EN ARCHIVO ENVIRONMENTS
      const payload = await this.jwtService.verify(token, {
        secret: process.env.JWT_SEED,
      });

      const user = await this.authService.findOneById(payload.id);
      if (!user) throw new UnauthorizedException('INVALID_USER');

      if (!user.isActive) throw new UnauthorizedException('USER_INACTIVE');
      request['user'] = user;
      return true;
    } catch (error) {
      throw new UnauthorizedException('NOT_VALID_TOKEN');
    }
  }

  private extractTokenFromHeader(request: Request): string {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
