import {
  Controller,
  Get,
  Post,
  Body,
  BadRequestException,
  UseGuards,
  Request,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from './dto/create-auth.dto';
import { LoginUserDto } from './dto/login-user.dto';
import { RegisterUserDto } from './dto/register-auth.dto';
import { AuthGuard } from './guards/auth.guard';
import { Request as RequestHttp } from 'express';
import { LoginResponse } from './interfaces/login-reponse.interface';
import { User } from './entities/auth.entity';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post()
  async create(@Body() createAuthDto: CreateUserDto) {
    try {
      const user = await this.authService.getUserByEmail(createAuthDto.email);

      if (user) {
        throw new BadRequestException('EMAIL_IN_USE');
        // throw new UnauthorizedException('Not valid credentials -email');
      }

      return await this.authService.create(createAuthDto);
    } catch (error) {
      console.log(error);
      if (error.message === 'EMAIL_IN_USE')
        throw new BadRequestException(error.message);
      throw new BadRequestException('Something went wrong');
    }
  }

  @Post('/login')
  login(@Body() loginUserDto: LoginUserDto) {
    try {
      return this.authService.login(loginUserDto);
    } catch (error) {
      console.log(error);
      throw new BadRequestException('Something went wrong');
    }
  }
  @Post('/register')
  async register(@Body() registerDto: RegisterUserDto) {
    try {
      const user = await this.authService.getUserByEmail(registerDto.email);

      if (user) {
        throw new BadRequestException('EMAIL_IN_USE');
        // throw new UnauthorizedException('Not valid credentials -email');
      }
      return this.authService.register(registerDto);
    } catch (error) {
      console.log(error);
      if (error.message === 'EMAIL_IN_USE')
        throw new BadRequestException(error.message);
      throw new BadRequestException('Something went wrong');
    }
  }
  @UseGuards(AuthGuard)
  @Get()
  findAll(@Request() req: RequestHttp) {
    const user = req['user'];
    // console.log(req);
    return user;
    return this.authService.findAll();
  }

  @UseGuards(AuthGuard)
  @Get('/check-token')
  async checkToken(@Request() req: RequestHttp): Promise<LoginResponse> {
    const user = req['user'] as User;
    return {
      user,
      token: this.authService.getJwtToken({ id: user._id }),
    };
  }
}
