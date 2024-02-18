import {
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import { AuthDto } from './dto';
import { PrismaService } from '@/prisma/prisma.service';
import { User } from '@prisma/client';

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
      const hash = await this.hashData(dto.password);

      // Save the new user in the database
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          password: hash,
        },
      });

      const tokens = await this.getTokens(user.id, user.email);
      await this.updateRefreshToken(user.id, tokens.refresh_token);

      return tokens;
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

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRefreshToken(user.id, tokens.refresh_token);

    return tokens;
  }

  async signout(userId: string) {
    await this.prisma.user.update({
      where: { id: userId },
      data: { refreshToken: '' },
    });

    return { success: true };
  }

  async refreshTokens(user: User, refreshToken: string) {
    const matches = await argon.verify(user.refreshToken, refreshToken);

    if (!matches) {
      throw new UnauthorizedException();
    }

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRefreshToken(user.id, tokens.refresh_token);

    return tokens;
  }

  hashData(data: string) {
    return argon.hash(data);
  }

  async updateRefreshToken(userId: string, refreshToken: string) {
    const hashedRefreshToken = await this.hashData(refreshToken);
    await this.prisma.user.update({
      where: { id: userId },
      data: { refreshToken: hashedRefreshToken },
    });
  }

  async getTokens(
    userId: string,
    email: string,
  ): Promise<{ access_token: string; refresh_token: string }> {
    const access_token = await this.jwt.signAsync(
      {
        sub: userId,
        email,
      },
      {
        expiresIn: '15m',
        secret: this.config.get('JWT_ACCESS_SECRET'),
      },
    );

    const refresh_token = await this.jwt.signAsync(
      { sub: userId },
      {
        expiresIn: '1d',
        secret: this.config.get('JWT_REFRESH_SECRET'),
      },
    );

    return { access_token, refresh_token };
  }
}
