import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import { RpcException } from '@nestjs/microservices';

import * as bcrypt from 'bcrypt';

import { LoginUserDto, RegisterUserDto } from './dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { envs } from 'src/config';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
  private readonly logger = new Logger('AuthService');

  constructor(private readonly jwtService: JwtService) {
    super();
  }

  onModuleInit() {
    this.$connect();
    this.logger.log('Mongo Database connected');
  }

  async verifyToken(token: string) {
    try {
      const { sub, iat, exp, ...user } = this.jwtService.verify(token, {
        secret: envs.jwtSecret,
      });
      console.log({ sub, iat, exp });
      return {
        user: user,
        token: await this.signJwt(user),
      };
    } catch (error) {
      throw new RpcException({
        status: 401,
        message: 'Invalid token',
      });
    }
  }

  async signJwt(payload: JwtPayload) {
    return this.jwtService.sign(payload);
  }

  async registerUser(registerUserDto: RegisterUserDto) {
    const { name, email, password } = registerUserDto;

    try {
      const user = await this.user.findUnique({
        where: { email },
      });
      if (user) {
        throw new RpcException({
          status: 400,
          message: `User ${email} already registered`,
        });
      }
      const newUser = await this.user.create({
        data: {
          name: name,
          password: bcrypt.hashSync(password, 10),
          email: email,
        },
      });
      const { password: __, ...rest } = newUser;
      console.log(__);
      return {
        user: rest,
        token: await this.signJwt(rest),
      };
    } catch (error) {
      throw new RpcException({
        status: 400,
        message: error.message,
      });
    }
  }

  async loginUser(loginUserDto: LoginUserDto) {
    const { email, password } = loginUserDto;

    try {
      const user = await this.user.findUnique({
        where: { email },
      });
      if (!user) {
        throw new RpcException({
          status: 400,
          message: `Email/Password is wrong!`,
        });
      }
      const { password: __, ...rest } = user;
      const isValidPassword = bcrypt.compareSync(password, __);
      if (!isValidPassword) {
        throw new RpcException({
          status: 400,
          message: `Email/Password is wrong!`,
        });
      }
      return {
        user: rest,
        token: await this.signJwt(rest),
      };
    } catch (error) {
      throw new RpcException({
        status: 400,
        message: error.message,
      });
    }
  }
}
