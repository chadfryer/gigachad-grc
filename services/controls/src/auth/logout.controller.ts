import {
  Controller,
  Post,
  Body,
  UseGuards,
  Req,
  HttpCode,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { Throttle } from '@nestjs/throttler';
import { ApiTags, ApiBearerAuth, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { Request } from 'express';
import { DevAuthGuard } from './dev-auth.guard';
import { LogoutService } from './logout.service';
import { LogoutDto, LogoutAllDevicesDto, LogoutResponseDto } from './dto/logout.dto';
import { CurrentUser, UserContext } from '@gigachad-grc/shared';

// Extend Request to include token info
interface AuthenticatedRequest extends Request {
  user: UserContext;
  tokenJti?: string;
  tokenExp?: number;
}

@ApiTags('Authentication')
@ApiBearerAuth()
@UseGuards(DevAuthGuard)
@Controller('api/auth')
export class LogoutController {
  private readonly logger = new Logger(LogoutController.name);

  constructor(private readonly logoutService: LogoutService) {}

  @Throttle({ default: { limit: 5, ttl: 60000 } }) // 5 requests per minute
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Logout current session and revoke token' })
  @ApiResponse({ status: 200, type: LogoutResponseDto, description: 'Logged out successfully' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async logout(
    @CurrentUser() user: UserContext,
    @Req() request: AuthenticatedRequest,
    @Body() dto: LogoutDto
  ): Promise<LogoutResponseDto> {
    const jti = request.tokenJti;
    const exp = request.tokenExp;

    this.logger.log(`Logout request from user ${user.userId}`);

    if (jti && exp) {
      const expiresAt = new Date(exp * 1000);
      await this.logoutService.revokeCurrentToken(
        jti,
        user.userId,
        expiresAt,
        dto.reason || 'logout'
      );
    }

    return {
      success: true,
      message: 'Successfully logged out',
      revokedCount: jti ? 1 : 0,
    };
  }

  @Throttle({ default: { limit: 3, ttl: 60000 } }) // 3 requests per minute
  @Post('logout-all')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Logout all sessions and revoke all tokens for current user' })
  @ApiResponse({ status: 200, type: LogoutResponseDto, description: 'All sessions logged out' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async logoutAll(
    @CurrentUser() user: UserContext,
    @Req() request: AuthenticatedRequest,
    @Body() dto: LogoutAllDevicesDto
  ): Promise<LogoutResponseDto> {
    const exp = request.tokenExp;

    this.logger.log(`Logout all devices request from user ${user.userId}`);

    // Default to 24 hours from now if no exp available
    const expiresAt = exp ? new Date(exp * 1000) : new Date(Date.now() + 24 * 60 * 60 * 1000);

    const revokedCount = await this.logoutService.revokeAllUserTokens(
      user.userId,
      expiresAt,
      dto.reason || 'logout_all_devices'
    );

    return {
      success: true,
      message: `Successfully logged out from all devices`,
      revokedCount,
    };
  }
}
