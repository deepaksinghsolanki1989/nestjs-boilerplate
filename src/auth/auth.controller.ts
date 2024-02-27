import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  UseGuards,
} from '@nestjs/common';
import { User } from '@prisma/client';
import { AuthService } from './auth.service';
import { GetHeaders, GetUser } from './decorator';
import { AuthDto } from './dto';
import { AccessTokenGuard, RefreshTokenGuard } from './guard';

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
  @Get('refresh-token')
  refreshTokens(
    @GetUser() user: User,
    @GetHeaders('authorization') refreshToken: string,
  ) {
    return this.authService.refreshTokens(user, refreshToken);
  }
}
