import { createParamDecorator, ExecutionContext } from '@nestjs/common';

export const GetHeaders = createParamDecorator(
  (data: string | undefined, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();

    if (data) {
      const header = request.headers[data];
      return data === 'authorization'
        ? header.replace('Bearer', '').trim()
        : header;
    }

    return request.headers;
  },
);
