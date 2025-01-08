import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';

import * as bcryptjs from 'bcryptjs';

import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { User } from './entities/user.entity';
import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';
import { RegisterUserDto } from './dto/register-user.dto';



@Injectable()
export class AuthService {

  constructor(
    @InjectModel( User.name ) 
    private userModel: Model<User>,
    private jwtService: JwtService,
  ){}



  //Creamos un nuevo usuario
  async create(createUserDto: CreateUserDto): Promise<User> {
    try{
      const { password, ...userdata } = createUserDto;
      const newUser = new this.userModel({
        password: bcryptjs.hashSync( password, 10 ),
        ...userdata
      });
      
      await newUser.save();

      const { password:_, ...user } = newUser.toJSON();

      return user;

    
    }catch(error){
      if( error.code === 11000 ){
        throw new BadRequestException( ` ${ createUserDto.email } alredy exists!` )
      }
      throw new InternalServerErrorException('Something terrible happen!!');
    }
  }



  //Registro de un usuario
  async register(regiterDto: RegisterUserDto): Promise<LoginResponse>{
    const user = await this.create(regiterDto);

    return {
      user: user,
      token: this.getJwtToken({ id: user._id }),
    }
  }



  //Método de logueo
  async login( loginDto: LoginDto ): Promise<LoginResponse>{
    const { email, password } = loginDto;

    const user = await this.userModel.findOne({ email });

    if( !user ){
      throw new UnauthorizedException('Not valid credentials - email');
    }

    if( !bcryptjs.compareSync( password, user.password ) ){
      throw new UnauthorizedException('Not valid credentials - password');
    }

    const { password:_, ...rest } = user.toJSON(); 
    
    return {
      user: rest,
      token: this.getJwtToken({ id: user.id }),
    };

  }



  //Listar los usuarios registrados
  findAll(): Promise<User[]> {
    return this.userModel.find();
  }



  //Busca un usuario por id
  async findUserById( id: string ){
    const user = await this.userModel.findById( id );
    const {password, ...rest} = user.toJSON();

    return rest;
  }



//Obtenemos un JWT  
getJwtToken( payload: JwtPayload ): string{
    const token = this.jwtService.sign(payload);
    return token;
  }




/*
  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateUserDto: UpdateUserDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }



  
*/

}
