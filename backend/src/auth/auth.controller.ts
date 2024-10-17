import { Controller, Post, UseGuards, Body, Get, Req } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignUpDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';
import { JwtAuthGuard } from './local.auth';
import { Role } from './role.enum';
import { Roles } from './roles.decorator';

@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService) { }

    @Post('signup')
    async signUp(@Body() signUpDto:SignUpDto): Promise<{ token: string }> {
        return this.authService.signUp(signUpDto);
    }

    @Post('login')
    async login(@Body() loginDto:LoginDto): Promise<{ token: string }> {
        return this.authService.login(loginDto);
    }

    @Get('profile')
    @UseGuards(JwtAuthGuard)
    @Roles(Role.Admin)
    getProfile(@Req() req) {
        return "hello";  // Access the user from the request
      }

      @Get('user')
      @UseGuards(JwtAuthGuard)
      @Roles(Role.User)
      getUser(@Req() req) {
          return "User";  // Access the user from the request
        }
  
}