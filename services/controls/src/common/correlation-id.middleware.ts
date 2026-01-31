import { Injectable, NestMiddleware, Logger } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { randomUUID } from 'crypto';

const CORRELATION_ID_HEADER = 'x-request-id';

/**
 * Middleware to add correlation IDs to all requests.
 * 
 * If the client provides an X-Request-ID header, it will be used.
 * Otherwise, a new UUID will be generated.
 * 
 * The correlation ID is:
 * 1. Added to the request object for use in services
 * 2. Added to the response headers for client tracking
 * 3. Logged with each request for distributed tracing
 */
@Injectable()
export class CorrelationIdMiddleware implements NestMiddleware {
  private readonly logger = new Logger('HTTP');

  use(req: Request, res: Response, next: NextFunction) {
    // Get existing correlation ID or generate new one
    const correlationId = (req.headers[CORRELATION_ID_HEADER] as string) || randomUUID();
    
    // Attach to request for use in services
    (req as any).correlationId = correlationId;
    
    // Add to response headers so clients can track their requests
    res.setHeader(CORRELATION_ID_HEADER, correlationId);
    
    // Log request start with correlation ID
    const startTime = Date.now();
    const { method, originalUrl } = req;
    const userAgent = req.get('user-agent') || '-';
    const ip = this.getClientIp(req);
    
    // Log on response finish
    res.on('finish', () => {
      const duration = Date.now() - startTime;
      const { statusCode } = res;
      const contentLength = res.get('content-length') || '-';
      
      // Format: [correlationId] METHOD /path STATUS durationMs bytes
      const logMessage = `[${correlationId}] ${method} ${originalUrl} ${statusCode} ${duration}ms ${contentLength} bytes`;
      
      // Log at different levels based on status code
      if (statusCode >= 500) {
        this.logger.error(`${logMessage} ip=${ip} ua="${userAgent}"`);
      } else if (statusCode >= 400) {
        this.logger.warn(`${logMessage} ip=${ip}`);
      } else {
        this.logger.log(logMessage);
      }
    });
    
    next();
  }

  /**
   * Extract client IP from request
   */
  private getClientIp(req: Request): string {
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded) {
      const ips = Array.isArray(forwarded) ? forwarded[0] : forwarded;
      return ips.split(',')[0].trim();
    }
    
    const realIp = req.headers['x-real-ip'];
    if (realIp) {
      return Array.isArray(realIp) ? realIp[0] : realIp;
    }
    
    return req.ip || req.socket?.remoteAddress || 'unknown';
  }
}

/**
 * Helper function to get correlation ID from request
 */
export function getCorrelationId(req: any): string {
  return req?.correlationId || req?.headers?.[CORRELATION_ID_HEADER] || 'unknown';
}

/**
 * Type declaration for extended request
 */
declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      correlationId?: string;
    }
  }
}
