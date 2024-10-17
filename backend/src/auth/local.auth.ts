import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from './schemas/user.schema';
import { Request } from 'express';
import { ConfigService } from '@nestjs/config';
import { Reflector } from '@nestjs/core';
import { Role } from './role.enum';
import { ROLES_KEY } from './roles.decorator';

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(
    private jwtService: JwtService,
    @InjectModel(User.name) private userModel: Model<User>,
    private config: ConfigService,
    private reflector: Reflector
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();

    // Get required roles for the current route
    const requiredRoles = this.reflector.getAllAndOverride<Role[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    // Extract token and validate roles
    return await this.extractTokenFromHeader(request, requiredRoles);
  }

  async extractTokenFromHeader(request: Request, requiredRoles: Role[]): Promise<boolean> {
    const authHeader = request.headers['authorization'];
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.split(' ')[1];
      try {
        // Verify the token using JwtService
        const decoded = this.jwtService.verify(token, {
          secret: this.config.get<string>('JWT_SECRET'),
        });

        // Extract user ID and find the user in the database
        const user = await this.userModel.findById(decoded.id);
        if (!user) {
          throw new UnauthorizedException('User not found');
        }

        // Attach user object to the request
        request['user'] = user;
        // Check if user roles include any required role
        if(!user.role){
          throw new UnauthorizedException('there is no role assign to you');
        }
          const hasRole = requiredRoles.some((role) => user.role === role);
          if (!hasRole) {
            throw new UnauthorizedException('You do not have access to this resource');
          }
        

        return true;
      } catch (error) {
        // Handle token errors
        if (error.name === 'TokenExpiredError') {
          throw new UnauthorizedException('Token expired');
        }
        throw new UnauthorizedException('Invalid token');
      }
    }

    throw new UnauthorizedException('Authorization header is missing');
  }
}
