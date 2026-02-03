import { Injectable, Logger } from '@nestjs/common';
import Redis from 'ioredis';

export interface UserSession {
  id: string;
  userId: string;
  organizationId: string;
  deviceInfo?: string;
  ipAddress: string;
  userAgent?: string;
  createdAt: Date;
  lastActivityAt: Date;
  expiresAt: Date;
  isActive: boolean;
}

@Injectable()
export class RedisSessionStore {
  private readonly logger = new Logger(RedisSessionStore.name);
  private redis: Redis;
  private readonly SESSION_PREFIX = 'session:';
  private readonly USER_SESSIONS_PREFIX = 'user_sessions:';
  private readonly ORG_SESSIONS_PREFIX = 'org_sessions:';

  constructor() {
    const redisUrl = process.env.REDIS_URL || 'redis://localhost:6379';
    this.redis = new Redis(redisUrl);
    this.redis.on('error', (err) => this.logger.error('Redis connection error', err));
    this.redis.on('connect', () => this.logger.log('Connected to Redis for session storage'));
  }

  async createSession(session: UserSession): Promise<void> {
    const key = this.SESSION_PREFIX + session.id;
    const ttl = Math.floor((session.expiresAt.getTime() - Date.now()) / 1000);
    
    await this.redis.setex(key, ttl, JSON.stringify(session));
    await this.redis.sadd(this.USER_SESSIONS_PREFIX + session.userId, session.id);
    await this.redis.sadd(this.ORG_SESSIONS_PREFIX + session.organizationId, session.id);
  }

  async getSession(sessionId: string): Promise<UserSession | null> {
    const data = await this.redis.get(this.SESSION_PREFIX + sessionId);
    if (!data) return null;
    
    const session = JSON.parse(data);
    session.createdAt = new Date(session.createdAt);
    session.lastActivityAt = new Date(session.lastActivityAt);
    session.expiresAt = new Date(session.expiresAt);
    return session;
  }

  async updateSession(sessionId: string, updates: Partial<UserSession>): Promise<void> {
    const session = await this.getSession(sessionId);
    if (!session) return;
    
    const updated = { ...session, ...updates };
    const ttl = Math.floor((updated.expiresAt.getTime() - Date.now()) / 1000);
    
    if (ttl > 0) {
      await this.redis.setex(this.SESSION_PREFIX + sessionId, ttl, JSON.stringify(updated));
    }
  }

  async deleteSession(sessionId: string): Promise<void> {
    const session = await this.getSession(sessionId);
    if (session) {
      await this.redis.del(this.SESSION_PREFIX + sessionId);
      await this.redis.srem(this.USER_SESSIONS_PREFIX + session.userId, sessionId);
      await this.redis.srem(this.ORG_SESSIONS_PREFIX + session.organizationId, sessionId);
    }
  }

  async getUserSessions(userId: string): Promise<UserSession[]> {
    const sessionIds = await this.redis.smembers(this.USER_SESSIONS_PREFIX + userId);
    const sessions: UserSession[] = [];
    
    for (const id of sessionIds) {
      const session = await this.getSession(id);
      if (session && session.isActive) {
        sessions.push(session);
      } else if (!session) {
        await this.redis.srem(this.USER_SESSIONS_PREFIX + userId, id);
      }
    }
    
    return sessions;
  }

  async deleteAllUserSessions(userId: string): Promise<number> {
    const sessionIds = await this.redis.smembers(this.USER_SESSIONS_PREFIX + userId);
    let count = 0;
    
    for (const id of sessionIds) {
      await this.deleteSession(id);
      count++;
    }
    
    return count;
  }

  async deleteAllOrgSessions(organizationId: string): Promise<number> {
    const sessionIds = await this.redis.smembers(this.ORG_SESSIONS_PREFIX + organizationId);
    let count = 0;
    
    for (const id of sessionIds) {
      await this.deleteSession(id);
      count++;
    }
    
    return count;
  }

  async getActiveSessionCount(): Promise<number> {
    const keys = await this.redis.keys(this.SESSION_PREFIX + '*');
    return keys.length;
  }
}
