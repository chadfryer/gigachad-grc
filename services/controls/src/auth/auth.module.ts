import { Global, Module } from '@nestjs/common';
import { DevAuthGuard, RolesGuard, PermissionsGuard, PRISMA_SERVICE } from '@gigachad-grc/shared';
import { PrismaService } from '../prisma/prisma.service';

/**
 * AuthModule - Centralized authentication and authorization module
 *
 * This module provides all guards (DevAuthGuard, RolesGuard, PermissionsGuard)
 * as global providers so they can be used across all modules without
 * dependency resolution issues.
 *
 * @remarks
 * - DevAuthGuard is used for development authentication (bypasses Keycloak)
 * - RolesGuard enforces role-based access control (uses optional Reflector)
 * - PermissionsGuard enforces permission-based access control (uses optional Reflector)
 * - Guards use optional Reflector injection with fallback to shared instance
 */
@Global()
@Module({
  providers: [
    // Re-provide PrismaService for guard dependencies
    PrismaService,
    // Provide PrismaService under the token expected by DevAuthGuard
    {
      provide: PRISMA_SERVICE,
      useExisting: PrismaService,
    },
    // DevAuthGuard - development authentication guard
    DevAuthGuard,
    // RolesGuard and PermissionsGuard now use optional Reflector injection
    RolesGuard,
    PermissionsGuard,
  ],
  exports: [PrismaService, PRISMA_SERVICE, DevAuthGuard, RolesGuard, PermissionsGuard],
})
export class AuthModule {}
