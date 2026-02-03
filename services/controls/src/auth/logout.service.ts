import { Injectable, Logger } from '@nestjs/common';
import { TokenBlacklistService } from '@gigachad-grc/shared';

@Injectable()
export class LogoutService {
  private readonly logger = new Logger(LogoutService.name);

  constructor(private readonly tokenBlacklistService: TokenBlacklistService) {}

  /**
   * Revoke the current user's token
   */
  async revokeCurrentToken(
    jti: string,
    userId: string,
    expiresAt: Date,
    reason: string = 'logout',
  ): Promise<void> {
    await this.tokenBlacklistService.revokeToken(jti, userId, expiresAt, reason);
    this.logger.log(`Revoked token [REDACTED] for user ${userId}, reason: ${reason}`);
  }

  /**
   * Revoke all tokens for a user (logout all devices)
   */
  async revokeAllUserTokens(
    userId: string,
    expiresAt: Date,
    reason: string = 'logout_all',
  ): Promise<number> {
    const count = await this.tokenBlacklistService.revokeAllUserTokens(userId, expiresAt, reason);
    this.logger.log(`Revoked ${count} token(s) for user ${userId}, reason: ${reason}`);
    return count;
  }

  /**
   * Get blacklist statistics
   */
  async getBlacklistStats(): Promise<{ totalRevoked: number }> {
    return this.tokenBlacklistService.getBlacklistStats();
  }
}
