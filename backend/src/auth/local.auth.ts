import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Observable } from 'rxjs';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from './schemas/user.schema';
import { Request } from 'express'; // Ensure you're using Express' Request type

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(
    private jwtService: JwtService,
    @InjectModel(User.name) private userModel: Model<User>,
  ) {}

  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const request = context.switchToHttp().getRequest<Request>();

    return this.extractTokenFromHeader(request);
  }

  async extractTokenFromHeader(request: Request): Promise<boolean> {
    const authHeader = request.headers['authorization'];

    if (authHeader && authHeader.startsWith('Bearer')) {
      const token = authHeader.split(' ')[1];
      try {
        // Verify the token using JwtService
        const verification = this.jwtService.verify(token);

        // Extract the user ID from the token payload
        const { id } = verification;

        // Find the user by ID in the database
        const user = await this.userModel.findById(id);
        if (!user) {
          throw new UnauthorizedException('User not found');
        }

        // Attach the user object to the request object
        request['user'] = user;

        return true;
      } catch (error) {
        // Check if the error is due to an expired token
        if (error.name === 'TokenExpiredError') {
          throw new UnauthorizedException('Token expired');
        } else {
          throw new UnauthorizedException('Invalid token');
        }
      }
    }

    // If no authorization header is present, throw an exception
    if (!authHeader) {
      throw new UnauthorizedException('Authorization header is missing');
    }

    return false;
  }
}
