import { Body, Controller, Get, Post, UseGuards } from '@nestjs/common';
import { User } from '@prisma/client';
import { GetUser } from '@/auth/decorator';
import { AccessTokenGuard } from '@/auth/guard';
import { ChangePasswordDto, UpdateProfileDto } from './dto';
import { UserProfileService } from './user-profile.service';

@UseGuards(AccessTokenGuard)
@Controller()
export class UserProfileController {
  constructor(private userProfileService: UserProfileService) {}

  @Get('user/me')
  getMe(@GetUser() user: User) {
    delete user.password;

    return user;
  }

  @Post('change-password')
  changePassword(@GetUser() user: User, @Body() dto: ChangePasswordDto) {
    return this.userProfileService.changePassword(user, dto);
  }

  @Post('update-profile')
  updateProfile(@GetUser() user: User, @Body() dto: UpdateProfileDto) {
    return this.userProfileService.updateProfile(user.id, dto);
  }
}
