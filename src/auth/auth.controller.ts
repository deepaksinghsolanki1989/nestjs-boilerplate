import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';
import { GetHeaders, GetUser } from './decorator';
import { AccessTokenGuard, RefreshTokenGuard } from './guard';
import { User } from '@prisma/client';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('signup')
  signup(@Body() dto: AuthDto) {
    return this.authService.signup(dto);
  }

  @HttpCode(HttpStatus.OK)
  @Post('signin')
  signin(@Body() dto: AuthDto) {
    return this.authService.signin(dto);
  }

  @UseGuards(AccessTokenGuard)
  @Get('signout')
  signout(@GetUser('id') userId: string) {
    return this.authService.signout(userId);
  }

  @UseGuards(RefreshTokenGuard)
  @Get('refresh')
  refreshTokens(
    @GetUser() user: User,
    @GetHeaders('authorization') refreshToken: string,
  ) {
    return this.authService.refreshTokens(user, refreshToken);
  }
}
