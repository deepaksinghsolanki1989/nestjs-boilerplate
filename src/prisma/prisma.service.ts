import { Injectable } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

@Injectable()
export class PrismaService extends PrismaClient {
  constructor() {
    super({
      datasources: {
        db: {
          url: 'mongodb+srv://deepak:nR8rgr1i9BvXAYNu@dev.hzyajuj.mongodb.net/nestjs-boilerplate',
        },
      },
    });
  }
}
