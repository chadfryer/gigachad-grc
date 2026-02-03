import { Injectable, Logger } from '@nestjs/common';
import Redis from 'ioredis';

export interface RevokedToken {
  jti: string;
  userId: string;
  reason: string;
  revokedAt: Date;
  expiresAt: Date;
}

@Injectable()
export class TokenBlacklistService {
  private readonly logger = new Logger(TokenBlacklistService.name);
  private redis: Redis;
  private readonly BLACKLIST_PREFIX = 'token_blacklist:';
  private readonly USER_TOKENS_PREFIX = 'user_tokens:';

  constructor() {
    const redisUrl = process.env.REDIS_URL || 'redis://localhost:6379';
    this.redis = new Redis(redisUrl);
    this.redis.on('error', (err) => this.logger.error('Redis connection error', err));
  }

  async revokeToken(jti: string, userId: string, expiresAt: Date, reason: string = 'logout'): Promise<void> {
    const key = this.BLACKLIST_PREFIX + jti;
    const ttl = Math.max(0, Math.floor((expiresAt.getTime() - Date.now()) / 1000));
    
    if (ttl <= 0) {
      this.logger.debug(`Token [REDACTED] already expired, skipping blacklist`);
      return;
    }

    const entry: RevokedToken = {
      jti,
      userId,
      reason,
      revokedAt: new Date(),
      expiresAt,
    };

    await this.redis.setex(key, ttl, JSON.stringify(entry));
    await this.redis.sadd(this.USER_TOKENS_PREFIX + userId, jti);
    await this.redis.expire(this.USER_TOKENS_PREFIX + userId, ttl);
    
    this.logger.log(`Token [REDACTED] revoked for user ${userId}, reason: ${reason}`);
  }

  async isTokenRevoked(jti: string): Promise<boolean> {
    if (!jti) return false;
    const exists = await this.redis.exists(this.BLACKLIST_PREFIX + jti);
    return exists === 1;
  }

  async revokeAllUserTokens(userId: string, expiresAt: Date, reason: string = 'logout_all'): Promise<number> {
    const tokenIds = await this.redis.smembers(this.USER_TOKENS_PREFIX + userId);
    
    for (const jti of tokenIds) {
      await this.revokeToken(jti, userId, expiresAt, reason);
    }
    
    this.logger.log(`Revoked ${tokenIds.length} token(s) for user ${userId}`);
    return tokenIds.length;
  }

  async trackToken(jti: string, userId: string, expiresAt: Date): Promise<void> {
    const ttl = Math.max(0, Math.floor((expiresAt.getTime() - Date.now()) / 1000));
    if (ttl > 0) {
      await this.redis.sadd(this.USER_TOKENS_PREFIX + userId, jti);
      await this.redis.expire(this.USER_TOKENS_PREFIX + userId, ttl);
    }
  }

  async getBlacklistStats(): Promise<{ totalRevoked: number }> {
    const keys = await this.redis.keys(this.BLACKLIST_PREFIX + '*');
    return { totalRevoked: keys.length };
  }
}
