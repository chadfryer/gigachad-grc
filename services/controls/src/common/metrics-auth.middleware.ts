import { Injectable, NestMiddleware, UnauthorizedException, Logger } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { timingSafeEqual } from 'crypto';

/**
 * SECURITY: Middleware to protect the /metrics endpoint from unauthorized access.
 *
 * Metrics endpoints can expose sensitive system information including:
 * - Request counts and error rates
 * - Database connection counts
 * - Memory usage and performance characteristics
 * - Internal service topology
 *
 * This middleware requires one of:
 * - Bearer token matching METRICS_AUTH_TOKEN environment variable
 * - IP address in the allowed list (for internal Prometheus scraper)
 * - Basic auth credentials matching METRICS_AUTH_USER/METRICS_AUTH_PASSWORD
 */
@Injectable()
export class MetricsAuthMiddleware implements NestMiddleware {
  private readonly logger = new Logger(MetricsAuthMiddleware.name);
  private readonly metricsToken: string | undefined;
  private readonly metricsUser: string | undefined;
  private readonly metricsPassword: string | undefined;
  private readonly allowedIPs: string[];

  constructor() {
    this.metricsToken = process.env.METRICS_AUTH_TOKEN;
    this.metricsUser = process.env.METRICS_AUTH_USER;
    this.metricsPassword = process.env.METRICS_AUTH_PASSWORD;

    // Allow internal IPs by default (for Prometheus in Docker network)
    const allowedIPsEnv = process.env.METRICS_ALLOWED_IPS || '';
    this.allowedIPs = allowedIPsEnv
      ? allowedIPsEnv.split(',').map((ip) => ip.trim())
      : ['127.0.0.1', '::1', 'localhost'];

    // Add internal Docker network IPs if in production
    if (process.env.NODE_ENV === 'production') {
      // Common Docker internal networks
      this.allowedIPs.push('172.17.0.1', '172.18.0.1', '172.19.0.1', '172.20.0.1');
    }
  }

  use(req: Request, res: Response, next: NextFunction): void {
    // Check if metrics auth is disabled (development only)
    if (process.env.METRICS_AUTH_DISABLED === 'true' && process.env.NODE_ENV !== 'production') {
      return next();
    }

    // In production, always require some form of authentication
    if (process.env.NODE_ENV === 'production' && !this.metricsToken && !this.metricsUser) {
      this.logger.error(
        'SECURITY: Metrics endpoint accessed in production without auth configuration'
      );
      throw new UnauthorizedException('Metrics endpoint requires authentication in production');
    }

    // Check IP allowlist
    const clientIP = this.getClientIP(req);
    if (this.isIPAllowed(clientIP)) {
      return next();
    }

    // Check Bearer token
    const authHeader = req.headers.authorization;
    if (authHeader?.startsWith('Bearer ') && this.metricsToken) {
      const token = authHeader.substring(7);
      if (this.safeCompare(token, this.metricsToken)) {
        return next();
      }
    }

    // Check Basic auth
    if (authHeader?.startsWith('Basic ') && this.metricsUser && this.metricsPassword) {
      try {
        const base64Credentials = authHeader.substring(6);
        const credentials = Buffer.from(base64Credentials, 'base64').toString('utf-8');
        const [username, password] = credentials.split(':');

        if (
          this.safeCompare(username, this.metricsUser) &&
          this.safeCompare(password, this.metricsPassword)
        ) {
          return next();
        }
      } catch {
        // Invalid base64 or format - fall through to unauthorized
      }
    }

    this.logger.warn(
      `SECURITY: Unauthorized metrics access attempt from IP: ${clientIP}, ` +
        `User-Agent: ${req.headers['user-agent']}`
    );

    // Return 401 with WWW-Authenticate header for Basic auth prompt
    res.setHeader('WWW-Authenticate', 'Basic realm="Metrics"');
    throw new UnauthorizedException('Metrics endpoint requires authentication');
  }

  /**
   * Get the real client IP, handling proxies
   */
  private getClientIP(req: Request): string {
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded) {
      const ips = Array.isArray(forwarded) ? forwarded[0] : forwarded;
      return ips.split(',')[0].trim();
    }

    const realIP = req.headers['x-real-ip'];
    if (realIP) {
      return Array.isArray(realIP) ? realIP[0] : realIP;
    }

    return req.ip || req.socket.remoteAddress || 'unknown';
  }

  /**
   * Check if IP is in the allowed list
   */
  private isIPAllowed(ip: string): boolean {
    // Normalize IPv6-mapped IPv4 addresses
    const normalizedIP = ip.replace(/^::ffff:/, '');
    return this.allowedIPs.some((allowed) => {
      const normalizedAllowed = allowed.replace(/^::ffff:/, '');
      return normalizedIP === normalizedAllowed;
    });
  }

  /**
   * SECURITY: Timing-safe string comparison to prevent timing attacks
   */
  private safeCompare(a: string, b: string): boolean {
    if (a.length !== b.length) {
      return false;
    }
    try {
      return timingSafeEqual(Buffer.from(a, 'utf-8'), Buffer.from(b, 'utf-8'));
    } catch {
      return false;
    }
  }
}
