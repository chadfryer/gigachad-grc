import { Module } from '@nestjs/common';
import { LogoutController } from './logout.controller';
import { LogoutService } from './logout.service';
import { TokenBlacklistService } from '@gigachad-grc/shared';

@Module({
  controllers: [LogoutController],
  providers: [LogoutService, TokenBlacklistService],
  exports: [LogoutService, TokenBlacklistService],
})
export class LogoutModule {}
