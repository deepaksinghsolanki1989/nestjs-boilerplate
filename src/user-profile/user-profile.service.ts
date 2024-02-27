import { ForbiddenException, Injectable } from '@nestjs/common';
import * as argon from 'argon2';
import { ChangePasswordDto, UpdateProfileDto } from './dto';
import { PrismaService } from '@/prisma/prisma.service';
import { User } from '@prisma/client';

@Injectable()
export class UserProfileService {
  constructor(private prisma: PrismaService) {}

  async changePassword(user: User, dto: ChangePasswordDto) {
    // verify old password
    const passwordMatch = await argon.verify(
      user.password,
      dto.currentPassword,
    );

    // If password incorrect throw exception
    if (!passwordMatch) {
      throw new ForbiddenException('Old password does not matched');
    }

    // Generate the password hash
    const hash = await argon.hash(dto.newPassword);

    // Update password in the database
    await this.prisma.user.update({
      where: { id: user.id },
      data: { password: hash },
    });

    return { message: 'Password changed successfully' };
  }

  async updateProfile(id: string, data: UpdateProfileDto) {
    await this.prisma.user.update({
      where: { id },
      data,
    });

    return { message: 'Profile updated successfully' };
  }
}
