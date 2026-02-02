import { Injectable, CanActivate, ExecutionContext, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { DEV_USER, ensureDevUserExists } from '@gigachad-grc/shared';

/**
 * Development auth guard that bypasses JWT validation
 * and injects a mock user context
 *
 * WARNING: Only use in development mode
 * CRITICAL: This guard will throw an error in production
 *
 * AUTO-SYNC: Automatically ensures the mock user and organization
 * exist in the database to prevent foreign key constraint errors.
 */
@Injectable()
export class DevAuthGuard implements CanActivate {
  private readonly logger = new Logger(DevAuthGuard.name);
  private devUserSynced = false;

  constructor(private readonly prisma: PrismaService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // SECURITY: Prevent usage in production
    const nodeEnv = process.env.NODE_ENV || 'development';
    if (nodeEnv === 'production') {
      throw new Error(
        'SECURITY ERROR: DevAuthGuard is configured but NODE_ENV is set to production. ' +
          'This is a critical security vulnerability. Please use proper JWT authentication in production.'
      );
    }

    const request = context.switchToHttp().getRequest();

    // Auto-sync: Ensure mock user and organization exist in database
    if (!this.devUserSynced) {
      await ensureDevUserExists(this.prisma, this.logger);
      this.devUserSynced = true;
    }

    // Support header overrides for testing, with DEV_USER as fallback
    request.user = {
      userId: request.headers['x-user-id'] || DEV_USER.userId,
      organizationId: request.headers['x-organization-id'] || DEV_USER.organizationId,
      email: request.headers['x-user-email'] || DEV_USER.email,
      role: request.headers['x-user-role'] || 'admin',
    };

    return true;
  }
}
