import { Controller, Get, UseGuards } from '@nestjs/common';
import { User } from '@prisma/client';
import { GetUser } from '@/auth/decorator';
import { AccessTokenGuard } from '@/auth/guard';

@UseGuards(AccessTokenGuard)
@Controller('users')
export class UserController {
  @Get('me')
  getMe(@GetUser() user: User) {
    return user;
  }
}
