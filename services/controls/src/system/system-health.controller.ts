import { Controller, Get, UseGuards } from '@nestjs/common';
import { Throttle } from '@nestjs/throttler';
import { ApiTags, ApiBearerAuth, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { SystemHealthService } from './system-health.service';
import { DevAuthGuard } from '../auth/dev-auth.guard';
import { PermissionGuard } from '../auth/permission.guard';
import { RequirePermission } from '../auth/decorators/require-permission.decorator';
import { Resource, Action } from '../permissions/dto/permission.dto';
import {
  SystemHealthResponse,
  BackupStatusResponse,
  SetupStatusResponse,
  ProductionReadinessResponse,
} from './dto/system-health.dto';

@ApiTags('system')
@Controller('api/system')
export class SystemHealthController {
  constructor(private readonly systemHealthService: SystemHealthService) {}

  /**
   * Basic health check - no auth required
   * Used by load balancers and monitoring systems
   */
  @Throttle({ default: { limit: 60, ttl: 60000 } })
  @Get('health')
  @ApiOperation({ summary: 'Basic health check (no auth required)' })
  @ApiResponse({ status: 200, description: 'Service is healthy' })
  async healthCheck() {
    return {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      service: 'controls',
    };
  }

  /**
   * Comprehensive system health - requires admin
   */
  @Get('health/detailed')
  @UseGuards(DevAuthGuard, PermissionGuard)
  @RequirePermission(Resource.SETTINGS, Action.READ)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Detailed system health check (admin only)' })
  @ApiResponse({ status: 200, type: Object })
  async getDetailedHealth(): Promise<SystemHealthResponse> {
    return this.systemHealthService.getSystemHealth();
  }

  /**
   * Get backup status
   */
  @Get('backup/status')
  @UseGuards(DevAuthGuard, PermissionGuard)
  @RequirePermission(Resource.SETTINGS, Action.READ)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get backup configuration status' })
  @ApiResponse({ status: 200, type: Object })
  async getBackupStatus(): Promise<BackupStatusResponse> {
    return this.systemHealthService.getBackupStatus();
  }

  /**
   * Get setup status for first-run wizard
   */
  @Get('setup/status')
  @UseGuards(DevAuthGuard, PermissionGuard)
  @RequirePermission(Resource.SETTINGS, Action.READ)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get setup wizard status' })
  @ApiResponse({ status: 200, type: Object })
  async getSetupStatus(): Promise<SetupStatusResponse> {
    return this.systemHealthService.getSetupStatus();
  }

  /**
   * Get production readiness assessment
   */
  @Get('production-readiness')
  @UseGuards(DevAuthGuard, PermissionGuard)
  @RequirePermission(Resource.SETTINGS, Action.READ)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get production readiness score and recommendations' })
  @ApiResponse({ status: 200, type: Object })
  async getProductionReadiness(): Promise<ProductionReadinessResponse> {
    return this.systemHealthService.getProductionReadiness();
  }

  /**
   * Get all system warnings for dashboard display
   */
  @Get('warnings')
  @UseGuards(DevAuthGuard, PermissionGuard)
  @RequirePermission(Resource.SETTINGS, Action.READ)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get active system warnings for dashboard' })
  @ApiResponse({ status: 200, type: Object })
  async getSystemWarnings() {
    const health = await this.systemHealthService.getSystemHealth();
    const warnings = health.checks
      .filter((c) => c.status === 'warning' || c.status === 'critical')
      .map((c) => ({
        id: c.id,
        severity: c.status,
        category: c.category,
        title: c.name,
        message: c.message,
        recommendation: c.recommendation,
        documentationUrl: c.documentationUrl,
      }));

    return {
      hasWarnings: warnings.length > 0,
      count: warnings.length,
      warnings,
    };
  }
}
