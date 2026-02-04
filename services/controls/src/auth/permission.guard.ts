import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Logger,
  SetMetadata,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Request } from 'express';
import { PermissionsService } from '../permissions/permissions.service';
import {
  PERMISSION_KEY,
  PERMISSIONS_KEY,
  RequiredPermission,
} from './decorators/require-permission.decorator';
import { Resource } from '../permissions/dto/permission.dto';

/**
 * SECURITY: Public decorator to explicitly mark endpoints as publicly accessible.
 * Use this decorator on endpoints that should bypass permission checks.
 * Without @Public() or @RequirePermission(), access is DENIED by default.
 */
export const IS_PUBLIC_KEY = 'isPublic';
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);

/**
 * Request with optional user and params for permission checking
 */
interface PermissionCheckRequest extends Request {
  user?: {
    userId?: string;
    permissions?: string[];
  };
}

@Injectable()
export class PermissionGuard implements CanActivate {
  private readonly logger = new Logger(PermissionGuard.name);

  constructor(
    private reflector: Reflector,
    private permissionsService: PermissionsService
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // Get required permission from decorator
    const requiredPermission = this.reflector.getAllAndOverride<RequiredPermission>(
      PERMISSION_KEY,
      [context.getHandler(), context.getClass()]
    );

    const requiredPermissions = this.reflector.getAllAndOverride<RequiredPermission[]>(
      PERMISSIONS_KEY,
      [context.getHandler(), context.getClass()]
    );

    // SECURITY: Check for @Public() decorator - explicitly allows unauthenticated access
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (isPublic) {
      this.logger.debug('Public endpoint accessed - bypassing permission check');
      return true;
    }

    // SECURITY: Deny-by-default - if no @Public() or @RequirePermission() decorator,
    // deny access. This prevents accidental exposure of endpoints that forgot to add
    // security decorators.
    if (!requiredPermission && !requiredPermissions) {
      this.logger.warn(
        `Endpoint accessed without @Public() or @RequirePermission() decorator. ` +
          `Access DENIED by default. Add appropriate decorator to the handler.`
      );
      throw new ForbiddenException(
        'Access denied: endpoint requires explicit permission configuration'
      );
    }

    const request = context.switchToHttp().getRequest() as PermissionCheckRequest;

    // SECURITY: Use authenticated user context set by AuthGuard, NOT raw headers
    // This ensures the userId has been validated by the auth guard
    const userId = request.user?.userId;

    if (!userId) {
      this.logger.warn('No authenticated user context for permission check');
      throw new ForbiddenException('User not authenticated');
    }

    // Single permission check
    if (requiredPermission) {
      return this.checkPermission(requiredPermission, userId, request);
    }

    // Multiple permissions (OR logic)
    if (requiredPermissions && requiredPermissions.length > 0) {
      for (const perm of requiredPermissions) {
        try {
          const allowed = await this.checkPermission(perm, userId, request);
          if (allowed) return true;
        } catch {
          // Continue to next permission
        }
      }
      throw new ForbiddenException('Insufficient permissions');
    }

    return true;
  }

  private async checkPermission(
    permission: RequiredPermission,
    userId: string,
    request: PermissionCheckRequest
  ): Promise<boolean> {
    const { resource, action, resourceIdParam } = permission;

    // In dev mode, first check request.user.permissions (set by DevAuthGuard)
    const nodeEnv = process.env.NODE_ENV || 'development';
    if (nodeEnv !== 'production' && request.user?.permissions) {
      const requiredPerm = `${resource}:${action}`;
      if (request.user.permissions.includes(requiredPerm)) {
        this.logger.debug(`Permission granted via DevAuthGuard: ${requiredPerm}`);
        return true;
      }
    }

    // Get resource ID if specified
    let resourceId: string | undefined;
    if (resourceIdParam) {
      const body = request.body as Record<string, unknown> | undefined;
      const bodyValue = body?.[resourceIdParam];
      resourceId =
        request.params?.[resourceIdParam] ||
        (typeof bodyValue === 'string' ? bodyValue : undefined);
    }

    // Check permission based on resource type
    let result;
    if (resourceId) {
      // Use specific resource check for ownership validation
      switch (resource) {
        case Resource.CONTROLS:
          result = await this.permissionsService.canAccessControl(userId, resourceId, action);
          break;
        case Resource.EVIDENCE:
          result = await this.permissionsService.canAccessEvidence(userId, resourceId, action);
          break;
        case Resource.POLICIES:
          result = await this.permissionsService.canAccessPolicy(userId, resourceId, action);
          break;
        default:
          result = await this.permissionsService.hasPermission(userId, resource, action);
      }
    } else {
      // General permission check without resource context
      result = await this.permissionsService.hasPermission(userId, resource, action);
    }

    if (!result.allowed) {
      this.logger.debug(
        `Permission denied for user ${userId}: ${resource}:${action} - ${result.reason}`
      );
      throw new ForbiddenException(result.reason || 'Insufficient permissions');
    }

    return true;
  }
}

/**
 * SECURITY: AuthenticatedGuard - validates that requests come from authenticated users.
 *
 * IMPORTANT: This guard relies on trusted headers (x-user-id, x-organization-id)
 * that MUST be set by a reverse proxy (e.g., Traefik, nginx, API Gateway) after
 * validating the user's JWT/session token.
 *
 * DO NOT expose services using this guard directly to the internet without a
 * properly configured reverse proxy that:
 * 1. Validates JWT tokens with Keycloak/your auth provider
 * 2. Strips any client-provided x-user-id/x-organization-id headers
 * 3. Sets these headers ONLY after successful authentication
 *
 * For direct client access, use a full JWT validation guard instead.
 */
@Injectable()
export class AuthenticatedGuard implements CanActivate {
  private readonly logger = new Logger(AuthenticatedGuard.name);

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();
    const userId = request.headers['x-user-id'];
    const organizationId = request.headers['x-organization-id'];

    // SECURITY: Validate that required auth headers are present
    // These headers should ONLY be set by a trusted reverse proxy after JWT validation
    if (!userId) {
      this.logger.warn('Request missing x-user-id header - authentication failed');
      throw new ForbiddenException('User not authenticated');
    }

    if (!organizationId) {
      this.logger.warn('Request missing x-organization-id header - authentication failed');
      throw new ForbiddenException('Organization context not provided');
    }

    // SECURITY: Basic format validation to catch obvious spoofing attempts
    // Note: Real validation happens at the reverse proxy level
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!uuidRegex.test(userId)) {
      this.logger.warn(`Invalid x-user-id format: ${userId}`);
      throw new ForbiddenException('Invalid user identifier');
    }

    if (!uuidRegex.test(organizationId)) {
      this.logger.warn(`Invalid x-organization-id format: ${organizationId}`);
      throw new ForbiddenException('Invalid organization identifier');
    }

    // SECURITY: Attach validated values to request for downstream use
    request.user = {
      ...request.user,
      userId,
      organizationId,
    };

    return true;
  }
}
