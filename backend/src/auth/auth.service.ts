import {
  Injectable,
  NotAcceptableException,
  UnauthorizedException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from './schemas/user.schema';
import { SignUpDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';

@Injectable()
export class AuthService {
  constructor(
    private jwtService: JwtService,
    @InjectModel(User.name) private userModel: Model<User>,
  ) {}
  async signUp(
    signUpDto: SignUpDto,
  ): Promise<{ message: string; token: string }> {
    try {
      const { name, email,role, password } = signUpDto;
      const hashedPassword = await bcrypt.hash(password, 10);

      const user = await this.userModel.create({
        name,
        email,
        role,
        password: hashedPassword,
      });
      const token = this.jwtService.sign({ id: user._id });
      return { message: 'successfullfy sign Up', token };
    } catch (error) {
      if (error.code === 11000) {
        throw new NotAcceptableException('Email already exists');
      }
      throw new Error('An error occurred during sign up');
    }
  }

  async login(loginDto: LoginDto): Promise<{ message: string; token: string }> {
    const { email, password } = loginDto;

    const user = await this.userModel.findOne({ email });
    if (!user) {
      throw new UnauthorizedException('invalid email or password');
    }
    const isPasswordMatch = await bcrypt.compare(password, user.password);

    if (!isPasswordMatch) {
      throw new UnauthorizedException('invalid email or password');
    }
    const token = this.jwtService.sign({ id: user._id });
    return { message: 'successfullfy login', token };
  }
   
}
