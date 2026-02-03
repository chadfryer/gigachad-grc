import { Injectable, Logger, ExecutionContext, HttpException, HttpStatus } from '@nestjs/common';
import { SetMetadata } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { CanActivate } from '@nestjs/common';

export const ENDPOINT_RATE_LIMIT_KEY = 'endpointRateLimit';

export interface EndpointRateLimitConfig {
  windowMs: number;
  maxRequests: number;
  keyPrefix?: string;
  message?: string;
}

export const EndpointRateLimit = (config: EndpointRateLimitConfig) => SetMetadata(ENDPOINT_RATE_LIMIT_KEY, config);

interface RateLimitEntry {
  count: number;
  resetAt: number;
}

@Injectable()
export class RateLimiterGuard implements CanActivate {
  private readonly logger = new Logger(RateLimiterGuard.name);
  private readonly store = new Map<string, RateLimitEntry>();
  
  constructor(private reflector: Reflector) {
    setInterval(() => this.cleanup(), 60000);
  }
  
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const config = this.reflector.get<EndpointRateLimitConfig>(ENDPOINT_RATE_LIMIT_KEY, context.getHandler());
    
    if (!config) {
      return true;
    }
    
    const request = context.switchToHttp().getRequest();
    const key = this.getKey(request, config.keyPrefix || '');
    const now = Date.now();
    
    let entry = this.store.get(key);
    
    if (!entry || entry.resetAt <= now) {
      entry = { count: 0, resetAt: now + config.windowMs };
      this.store.set(key, entry);
    }
    
    entry.count++;
    
    if (entry.count > config.maxRequests) {
      const retryAfter = Math.ceil((entry.resetAt - now) / 1000);
      this.logger.warn(`Rate limit exceeded for ${key}`);
      
      throw new HttpException({
        statusCode: HttpStatus.TOO_MANY_REQUESTS,
        message: config.message || 'Too many requests, please try again later',
        retryAfter,
      }, HttpStatus.TOO_MANY_REQUESTS);
    }
    
    return true;
  }
  
  private getKey(request: any, prefix: string): string {
    const userId = request.user?.userId || request.user?.sub || 'anonymous';
    const ip = request.ip || request.connection?.remoteAddress || 'unknown';
    const path = request.route?.path || request.url;
    return `${prefix}:${userId}:${ip}:${path}`;
  }
  
  private cleanup(): void {
    const now = Date.now();
    for (const [key, entry] of this.store.entries()) {
      if (entry.resetAt <= now) {
        this.store.delete(key);
      }
    }
  }
}

export const ENDPOINT_RATE_LIMITS = {
  EXPORT: { windowMs: 60000, maxRequests: 5, keyPrefix: 'export', message: 'Export rate limit exceeded' },
  BULK_OPERATION: { windowMs: 60000, maxRequests: 10, keyPrefix: 'bulk', message: 'Bulk operation rate limit exceeded' },
  API_KEY: { windowMs: 3600000, maxRequests: 20, keyPrefix: 'apikey', message: 'API key operation rate limit exceeded' },
  FILE_UPLOAD: { windowMs: 60000, maxRequests: 10, keyPrefix: 'upload', message: 'Upload rate limit exceeded' },
  SEED: { windowMs: 3600000, maxRequests: 3, keyPrefix: 'seed', message: 'Seed operation rate limit exceeded' },
  CONFIG: { windowMs: 300000, maxRequests: 5, keyPrefix: 'config', message: 'Config operation rate limit exceeded' },
  WEBHOOK: { windowMs: 60000, maxRequests: 30, keyPrefix: 'webhook', message: 'Webhook rate limit exceeded' },
  DEFAULT: { windowMs: 60000, maxRequests: 100, keyPrefix: 'default' },
};
