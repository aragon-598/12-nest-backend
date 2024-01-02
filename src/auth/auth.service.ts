import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose'; 
import { JwtService } from '@nestjs/jwt';
import { Model } from 'mongoose';

import * as bcryptjs from "bcryptjs";

import { CreateUserDto } from './dto/create-user.dto';
import { JwtPayload } from './interfaces/jwt.payload';
import { LoginDto, RegisterUserDto, UpdateAuthDto } from './dto';
import { User } from './entities/user.entity';
import { LoginResponse } from './interfaces/login-response.interface';

@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    private jwtService: JwtService
  ){}

  async create(createUserDto: CreateUserDto): Promise<User> {
    
    try {
      //1 encriptar contraseñas
      const {password, ...userData} = createUserDto;
      const newUser = new this.userModel({
        password: bcryptjs.hashSync(password,10),
        ...userData
      });
      
      

      //2 guardar usuario

      //3 generar jwt
  
      await newUser.save();
      const {password:_, ...user} = newUser.toJSON();

      return user;
      
    } catch (error) {
      if(error.code === 11000){
        throw new BadRequestException(`${createUserDto.email} already exists`);
      }

      throw new InternalServerErrorException('Something terrible happen');
      
    }
  }

  async register(registerUserDto: RegisterUserDto):Promise<LoginResponse> {

    try {
      const user  = await this.create(registerUserDto);
      return {
        user,
        token: this.getJwt({id: user._id})
      };
    } catch (error) {
      throw error;
    }
  }

  async login(loginDto:LoginDto):Promise<LoginResponse>{
    const {email,password} = loginDto;

    const user = await this.userModel.findOne({email});
    if(!user)
      throw new UnauthorizedException('Invalid credentials - email');
    
    if(!bcryptjs.compareSync(password,user.password))
      throw new UnauthorizedException('Invalid credentials - password');

      const {password:_, ...data} = user.toJSON();

    return {
      user: data,
      token: this.getJwt({id:user.id})
    };
  }

  findAll() {
    return `This action returns all auth`;
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

  getJwt(payload: JwtPayload){
    const token = this.jwtService.sign(payload);
    return token;
  }
}
