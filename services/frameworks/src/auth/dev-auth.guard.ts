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

    // Mock user context for development
    request.user = {
      userId: DEV_USER.userId,
      keycloakId: DEV_USER.keycloakId,
      email: DEV_USER.email,
      organizationId: DEV_USER.organizationId,
      role: 'admin',
      permissions: [
        'controls:read',
        'controls:write',
        'controls:delete',
        'evidence:read',
        'evidence:write',
        'evidence:delete',
        'frameworks:read',
        'frameworks:write',
        'policies:read',
        'policies:write',
        'integrations:read',
        'integrations:write',
        'users:read',
        'users:write',
        'settings:read',
        'settings:write',
        'audit:read',
      ],
    };

    return true;
  }
}
