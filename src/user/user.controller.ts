import { Controller, UseGuards } from '@nestjs/common';
import { AccessTokenGuard } from '@/auth/guard';

@UseGuards(AccessTokenGuard)
@Controller('users')
export class UserController {}
