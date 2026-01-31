import { Injectable, ExecutionContext } from '@nestjs/common';
import { ThrottlerGuard, ThrottlerException } from '@nestjs/throttler';

/**
 * Custom throttler guard that extracts client identifier for rate limiting
 * 
 * Rate limiting is applied based on:
 * 1. IP address for unauthenticated requests
 * 2. User ID + IP for authenticated requests
 * 3. API Key for API requests
 */
@Injectable()
export class CustomThrottlerGuard extends ThrottlerGuard {
  /**
   * Get a unique identifier for the requesting client
   */
  protected async getTracker(req: Record<string, any>): Promise<string> {
    // Extract IP address
    const ip = req.ip || 
               req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
               req.headers['x-real-ip'] ||
               req.connection?.remoteAddress ||
               'unknown';

    // If authenticated, include user ID for per-user limiting
    const userId = req.user?.userId || req.headers['x-user-id'];
    
    // If API key, use API key hash
    const apiKey = req.headers['x-api-key'];
    
    if (apiKey) {
      // Hash the API key for the tracker (don't store raw key)
      const crypto = await import('crypto');
      const keyHash = crypto.createHash('sha256').update(apiKey).digest('hex').substring(0, 16);
      return `api:${keyHash}`;
    }
    
    if (userId) {
      return `user:${userId}:${ip}`;
    }
    
    return `ip:${ip}`;
  }

  /**
   * Override to customize the throttle key per request
   */
  protected generateKey(
    context: ExecutionContext,
    tracker: string,
    throttlerName: string,
  ): string {
    const req = context.switchToHttp().getRequest();
    const path = req.route?.path || req.url;
    
    // Create a key that includes the path for endpoint-specific limiting
    return `${throttlerName}:${tracker}:${path}`;
  }

  /**
   * Handle throttle exceptions with detailed logging
   */
  protected async throwThrottlingException(
    context: ExecutionContext,
    _throttlerLimitDetail: any,
  ): Promise<void> {
    const req = context.switchToHttp().getRequest();
    const tracker = await this.getTracker(req);
    
    // Log rate limit hit for monitoring
    console.warn(`[RateLimit] Limit exceeded for ${tracker} on ${req.url}`);
    
    throw new ThrottlerException(`Too many requests. Please try again later.`);
  }

  /**
   * Skip rate limiting for certain paths (health checks, etc.)
   */
  protected async shouldSkip(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest();
    const path = req.url;
    
    // Skip rate limiting for health checks and metrics
    const skipPaths = ['/health', '/api/health', '/metrics', '/api/docs'];
    
    return skipPaths.some(skip => path.startsWith(skip));
  }
}

/**
 * Rate limit configuration presets
 */
export const RateLimitPresets = {
  // Standard API endpoints
  standard: {
    ttl: 60000,  // 1 minute window
    limit: 100,  // 100 requests per minute
  },
  
  // Strict limit for auth endpoints
  auth: {
    ttl: 60000,  // 1 minute window
    limit: 5,    // 5 requests per minute
  },
  
  // Very strict for sensitive operations
  sensitive: {
    ttl: 60000,  // 1 minute window
    limit: 3,    // 3 requests per minute
  },
  
  // Relaxed for read-heavy endpoints
  relaxed: {
    ttl: 60000,  // 1 minute window
    limit: 200,  // 200 requests per minute
  },
  
  // Export operations (resource intensive)
  export: {
    ttl: 60000,  // 1 minute window
    limit: 10,   // 10 requests per minute
  },
  
  // Seed/demo data operations
  seed: {
    ttl: 60000,  // 1 minute window
    limit: 1,    // 1 request per minute
  },
};

/**
 * Decorator for applying custom rate limits to specific endpoints
 */
export function RateLimit(preset: keyof typeof RateLimitPresets | { ttl: number; limit: number }) {
  const config = typeof preset === 'string' ? RateLimitPresets[preset] : preset;
  
  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    // Store rate limit config as metadata
    Reflect.defineMetadata('rateLimit', config, target, propertyKey);
    return descriptor;
  };
}
