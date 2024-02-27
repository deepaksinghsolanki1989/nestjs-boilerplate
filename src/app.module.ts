import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AuthModule } from './auth/auth.module';
import { EmailModule } from './email/email.module';
import { PrismaModule } from './prisma/prisma.module';
import { UserModule } from './user/user.module';
import { UserProfileModule } from './user-profile/user-profile.module';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    AuthModule,
    EmailModule,
    UserModule,
    PrismaModule,
    UserProfileModule,
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}
