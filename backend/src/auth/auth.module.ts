import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
// import { UserModule } from '../users/users.module';
import { AuthService } from './auth.service';
// import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { AuthController } from './auth.controller';
import { MongooseModule } from '@nestjs/mongoose';
import { UserSchema } from './schemas/user.schema';
import { JwtAuthGuard } from './local.auth';

@Module({
  imports: [
    ConfigModule.forRoot(), // Initialize config globally
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        secret: config.get<string>('JWT_SECRET'), // Load JWT secret from env
        signOptions: { expiresIn: config.get<string | number>('JWT_EXPIRE') }, // Load JWT expire from env
      }),
    }),
    MongooseModule.forFeature([{ name: 'User', schema: UserSchema }]), 
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtAuthGuard], // Provide AuthService and UsersService
  exports: [AuthService, JwtAuthGuard], // Export AuthService if needed elsewhere
})
export class AuthModule {}
