import { Injectable, UnauthorizedException } from '@nestjs/common';
import { CreateUserDto } from './dto/create-auth.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './entities/auth.entity';
import { Model } from 'mongoose';
import { hash, compare } from 'bcrypt';
import { LoginUserDto } from './dto/login-user.dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { LoginResponse } from './interfaces/login-reponse.interface';
import { RegisterUserDto } from './dto';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    private jwtService: JwtService,
  ) {}

  async create(createUserDto: CreateUserDto): Promise<User> {
    const { password, ...userData } = createUserDto;
    const hashedPassword = await hash(password, 10);
    const newUser = await this.userModel.create({
      password: hashedPassword,
      ...userData,
    });

    // HAY TRES MANERAS DE HACER LO SIGUIENTE
    newUser.set('password', undefined);
    // O PODRÏAMOS TRAER EL USUARIO SIN TRAER LA CONTRASEÑA COMO LO SIGUIENTE
    // const userWithoutPassword = await this.userModel
    //   .findById(newUser._id)
    //   .select('-password')
    //   .exec();
    // O ALTERANDO EL USER DTO
    // const { password: _, ...userWithoutPassword } = newUser.toObject();
    // return userWithoutPassword;
    return newUser;
  }

  async getUserByEmail(email: string): Promise<User> {
    return await this.userModel.findOne({ email: email });
  }

  async login(loginUserDto: LoginUserDto): Promise<LoginResponse> {
    const { email, password } = loginUserDto;
    const user = await this.userModel.findOne({ email });
    // const user = await this.getUserByEmail(email);
    if (!user) {
      throw new UnauthorizedException('INCORRECT_EMAIL');
    }
    const passwordMatch = await compare(password, user.password);
    if (!passwordMatch) {
      throw new UnauthorizedException('INCORRECT_PASSWORD');
    }
    // const { password: _, ...rest } = user.toJSON();
    user.set('password', undefined);
    return {
      user,
      token: this.getJwtToken({ id: user.id }),
    };
  }

  async register(registerDto: RegisterUserDto): Promise<LoginResponse> {
    const user = await this.create(registerDto);
    const token = this.getJwtToken({ id: user._id });
    return {
      user,
      token,
    };
  }

  async findAll(): Promise<User[]> {
    return await this.userModel.find();
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJwtToken(payload: JwtPayload) {
    const token = this.jwtService.sign(payload);
    return token;
  }
}
