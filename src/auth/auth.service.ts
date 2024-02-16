import { ForbiddenException, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import { AuthDto } from './dto';
import { PrismaService } from '@/prisma/prisma.service';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}

  async signup(dto: AuthDto) {
    try {
      // Generate the password hash
      const hash = await argon.hash(dto.password);

      // Save the new user in the database
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          password: hash,
        },
      });

      // Return JWT Token
      return this.signToken(user.id, user.email);
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credencials taken');
        }
      }

      throw error;
    }
  }

  async signin(dto: AuthDto) {
    // Find the user by email
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });

    // If user does not exist throw exception
    if (!user) {
      throw new ForbiddenException('Credencials incorrect');
    }

    // Compare password
    const passwordMatch = await argon.verify(user.password, dto.password);

    // If password incorrect throw exception
    if (!passwordMatch) {
      throw new ForbiddenException('Credencials incorrect');
    }

    // Return JWT Token
    return this.signToken(user.id, user.email);
  }

  async signToken(
    userId: string,
    email: string,
  ): Promise<{ access_token: string }> {
    const payload = {
      sub: userId,
      email,
    };

    const secret = this.config.get('JWT_SECRET');
    const access_token = await this.jwt.signAsync(payload, {
      expiresIn: '15m',
      secret,
    });

    return { access_token };
  }
}
