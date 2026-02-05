import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuditLogFilterDto } from './dto/audit.dto';
import { Prisma, AuditLog } from '@prisma/client';
import { createHmac } from 'crypto';

export interface LogAuditParams {
  organizationId: string;
  userId?: string;
  userEmail?: string;
  userName?: string;
  action: string;
  entityType: string;
  entityId: string;
  entityName?: string;
  description: string;
  changes?: { before?: unknown; after?: unknown } | object;
  metadata?: Record<string, unknown>;
  ipAddress?: string;
  userAgent?: string;
}

/**
 * Result of audit log integrity verification
 */
export interface AuditLogIntegrityResult {
  valid: boolean;
  checkedCount: number;
  invalidLogs: { id: string; reason: string }[];
  chainBroken: boolean;
  chainBrokenAt?: string;
}

@Injectable()
export class AuditService {
  private readonly logger = new Logger(AuditService.name);

  /**
   * SECURITY: Secret key for HMAC signing of audit logs
   * This should be set via environment variable and kept secure
   */
  private readonly hmacKey: string;

  constructor(private prisma: PrismaService) {
    this.hmacKey = process.env.AUDIT_LOG_HMAC_KEY || '';

    if (!this.hmacKey) {
      this.logger.warn(
        'SECURITY WARNING: AUDIT_LOG_HMAC_KEY not set. ' +
          'Audit log integrity protection is disabled. ' +
          'Set this environment variable in production!'
      );
    }
  }

  /**
   * Generate HMAC signature for an audit log entry
   * Uses SHA-256 with the configured secret key
   */
  private generateLogSignature(
    logData: {
      organizationId: string;
      userId?: string;
      action: string;
      entityType: string;
      entityId: string;
      description: string;
      timestamp: Date;
      changes?: unknown;
      metadata?: unknown;
    },
    previousHash?: string
  ): string {
    if (!this.hmacKey) {
      return '';
    }

    // Create a deterministic string from log data
    const dataToSign = JSON.stringify({
      organizationId: logData.organizationId,
      userId: logData.userId || null,
      action: logData.action,
      entityType: logData.entityType,
      entityId: logData.entityId,
      description: logData.description,
      timestamp: logData.timestamp.toISOString(),
      changes: logData.changes || null,
      metadata: logData.metadata || null,
      previousHash: previousHash || null,
    });

    return createHmac('sha256', this.hmacKey).update(dataToSign).digest('hex');
  }

  /**
   * Get the hash of the most recent audit log for chain continuity
   */
  private async getLastLogHash(organizationId: string): Promise<string | undefined> {
    const lastLog = await this.prisma.auditLog.findFirst({
      where: { organizationId },
      orderBy: { timestamp: 'desc' },
      select: { id: true, metadata: true },
    });

    if (lastLog && lastLog.metadata) {
      const metadata = lastLog.metadata as Record<string, unknown>;
      return metadata.logHash as string | undefined;
    }

    return undefined;
  }

  /**
   * Verify the integrity of a single audit log entry
   */
  private verifyLogIntegrity(
    log: AuditLog,
    previousHash?: string
  ): { valid: boolean; reason?: string } {
    if (!this.hmacKey) {
      return { valid: true, reason: 'HMAC signing disabled' };
    }

    const metadata = log.metadata as Record<string, unknown> | null;
    const storedHash = metadata?.logHash as string | undefined;

    if (!storedHash) {
      return { valid: false, reason: 'Missing log signature' };
    }

    const expectedSignature = this.generateLogSignature(
      {
        organizationId: log.organizationId,
        userId: log.userId || undefined,
        action: log.action,
        entityType: log.entityType,
        entityId: log.entityId,
        description: log.description,
        timestamp: log.timestamp,
        changes: log.changes,
        metadata: { ...metadata, logHash: undefined, previousHash: undefined },
      },
      previousHash
    );

    if (storedHash !== expectedSignature) {
      return { valid: false, reason: 'Signature mismatch - log may have been tampered' };
    }

    return { valid: true };
  }

  /**
   * Log an audit event. This is the main method to call from other services.
   *
   * SECURITY: Each log entry is signed with HMAC-SHA256 and includes a hash chain
   * to the previous entry, enabling tamper detection.
   */
  async log(params: LogAuditParams): Promise<void> {
    try {
      const timestamp = new Date();

      // Get the hash of the previous log entry for chain integrity
      const previousHash = await this.getLastLogHash(params.organizationId);

      // Generate HMAC signature for this log entry
      const logSignature = this.generateLogSignature(
        {
          organizationId: params.organizationId,
          userId: params.userId,
          action: params.action,
          entityType: params.entityType,
          entityId: params.entityId,
          description: params.description,
          timestamp,
          changes: params.changes,
          metadata: params.metadata,
        },
        previousHash
      );

      // Include signature and previous hash in metadata
      const enhancedMetadata = {
        ...params.metadata,
        ...(logSignature ? { logHash: logSignature, previousHash } : {}),
      };

      await this.prisma.auditLog.create({
        data: {
          organizationId: params.organizationId,
          userId: params.userId,
          userEmail: params.userEmail,
          userName: params.userName,
          action: params.action,
          entityType: params.entityType,
          entityId: params.entityId,
          entityName: params.entityName,
          description: params.description,
          changes: params.changes as Prisma.InputJsonValue,
          metadata: enhancedMetadata as Prisma.InputJsonValue,
          ipAddress: params.ipAddress,
          userAgent: params.userAgent,
          timestamp,
        },
      });
    } catch (error) {
      // Log error but don't throw - audit logging should not break the main flow
      this.logger.error('Failed to create audit log:', error);
    }
  }

  /**
   * Verify integrity of audit logs for an organization
   *
   * SECURITY: Checks HMAC signatures and hash chain continuity to detect tampering.
   * Run this periodically or on-demand to ensure audit log integrity.
   *
   * @param organizationId - Organization to verify
   * @param limit - Maximum number of logs to check (default: 1000)
   * @returns Integrity verification result
   */
  async verifyAuditLogIntegrity(
    organizationId: string,
    limit = 1000
  ): Promise<AuditLogIntegrityResult> {
    if (!this.hmacKey) {
      this.logger.warn('Cannot verify audit log integrity: AUDIT_LOG_HMAC_KEY not configured');
      return {
        valid: true,
        checkedCount: 0,
        invalidLogs: [],
        chainBroken: false,
      };
    }

    // Fetch logs in chronological order (oldest first)
    const logs = await this.prisma.auditLog.findMany({
      where: { organizationId },
      orderBy: { timestamp: 'asc' },
      take: limit,
    });

    const result: AuditLogIntegrityResult = {
      valid: true,
      checkedCount: logs.length,
      invalidLogs: [],
      chainBroken: false,
    };

    let previousHash: string | undefined;

    for (const log of logs) {
      const metadata = log.metadata as Record<string, unknown> | null;
      const storedPreviousHash = metadata?.previousHash as string | undefined;

      // Check hash chain continuity
      if (previousHash !== undefined && storedPreviousHash !== previousHash) {
        result.chainBroken = true;
        result.chainBrokenAt = log.id;
        result.valid = false;
        result.invalidLogs.push({
          id: log.id,
          reason: 'Hash chain broken - previousHash mismatch',
        });
      }

      // Verify log signature
      const verification = this.verifyLogIntegrity(log, storedPreviousHash);
      if (!verification.valid) {
        result.valid = false;
        result.invalidLogs.push({
          id: log.id,
          reason: verification.reason || 'Unknown verification failure',
        });
      }

      // Update previousHash for next iteration
      previousHash = metadata?.logHash as string | undefined;
    }

    if (!result.valid) {
      this.logger.error(
        `SECURITY ALERT: Audit log integrity check failed for org ${organizationId}. ` +
          `Invalid logs: ${result.invalidLogs.length}, Chain broken: ${result.chainBroken}`
      );
    }

    return result;
  }

  /**
   * Find all audit logs with filtering and pagination
   */
  async findAll(organizationId: string, filters: AuditLogFilterDto) {
    const page = filters.page || 1;
    const limit = filters.limit || 50;
    const skip = (page - 1) * limit;
    const sortBy = filters.sortBy || 'timestamp';
    const sortOrder = filters.sortOrder || 'desc';

    const where: Prisma.AuditLogWhereInput = {
      organizationId,
    };

    if (filters.entityType) {
      where.entityType = filters.entityType;
    }

    if (filters.entityId) {
      where.entityId = filters.entityId;
    }

    if (filters.action) {
      where.action = filters.action;
    }

    if (filters.userId) {
      where.userId = filters.userId;
    }

    if (filters.search) {
      where.OR = [
        { entityName: { contains: filters.search, mode: 'insensitive' } },
        { description: { contains: filters.search, mode: 'insensitive' } },
        { userName: { contains: filters.search, mode: 'insensitive' } },
        { userEmail: { contains: filters.search, mode: 'insensitive' } },
      ];
    }

    if (filters.startDate || filters.endDate) {
      where.timestamp = {};
      if (filters.startDate) {
        where.timestamp.gte = new Date(filters.startDate);
      }
      if (filters.endDate) {
        where.timestamp.lte = new Date(filters.endDate);
      }
    }

    const [logs, total] = await Promise.all([
      this.prisma.auditLog.findMany({
        where,
        skip,
        take: limit,
        orderBy: { [sortBy]: sortOrder },
      }),
      this.prisma.auditLog.count({ where }),
    ]);

    return {
      data: logs,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
      },
    };
  }

  /**
   * Get a single audit log entry
   */
  async findOne(id: string, organizationId: string) {
    return this.prisma.auditLog.findFirst({
      where: {
        id,
        organizationId,
      },
    });
  }

  /**
   * Get audit logs for a specific entity
   */
  async findByEntity(organizationId: string, entityType: string, entityId: string, limit = 50) {
    return this.prisma.auditLog.findMany({
      where: {
        organizationId,
        entityType,
        entityId,
      },
      orderBy: { timestamp: 'desc' },
      take: limit,
    });
  }

  /**
   * Get audit statistics
   */
  async getStats(organizationId: string, startDate?: string, endDate?: string) {
    const where: Prisma.AuditLogWhereInput = { organizationId };

    if (startDate || endDate) {
      where.timestamp = {};
      if (startDate) {
        where.timestamp.gte = new Date(startDate);
      }
      if (endDate) {
        where.timestamp.lte = new Date(endDate);
      }
    }

    const [totalLogs, actionCounts, entityTypeCounts, userActivityCounts, recentActivity] =
      await Promise.all([
        this.prisma.auditLog.count({ where }),

        // Actions by type
        this.prisma.auditLog.groupBy({
          by: ['action'],
          where,
          _count: { action: true },
          orderBy: { _count: { action: 'desc' } },
          take: 10,
        }),

        // Entity types
        this.prisma.auditLog.groupBy({
          by: ['entityType'],
          where,
          _count: { entityType: true },
          orderBy: { _count: { entityType: 'desc' } },
        }),

        // Top users by activity
        this.prisma.auditLog.groupBy({
          by: ['userId', 'userName', 'userEmail'],
          where: {
            ...where,
            userId: { not: null },
          },
          _count: { userId: true },
          orderBy: { _count: { userId: 'desc' } },
          take: 10,
        }),

        // Recent activity (last 10)
        this.prisma.auditLog.findMany({
          where,
          orderBy: { timestamp: 'desc' },
          take: 10,
          select: {
            id: true,
            action: true,
            entityType: true,
            entityName: true,
            userName: true,
            timestamp: true,
            description: true,
          },
        }),
      ]);

    return {
      totalLogs,
      actionBreakdown: actionCounts.map((a) => ({
        action: a.action,
        count: a._count.action,
      })),
      entityTypeBreakdown: entityTypeCounts.map((e) => ({
        entityType: e.entityType,
        count: e._count.entityType,
      })),
      topUsers: userActivityCounts.map((u) => ({
        userId: u.userId,
        userName: u.userName,
        userEmail: u.userEmail,
        activityCount: u._count.userId,
      })),
      recentActivity,
    };
  }

  /**
   * Export audit logs as CSV-compatible data
   */
  async exportLogs(organizationId: string, filters: AuditLogFilterDto) {
    // Remove pagination for export
    const exportFilters = { ...filters, page: 1, limit: 10000 };
    const result = await this.findAll(organizationId, exportFilters);

    return result.data.map((log) => ({
      id: log.id,
      timestamp: log.timestamp.toISOString(),
      action: log.action,
      entityType: log.entityType,
      entityId: log.entityId,
      entityName: log.entityName || '',
      description: log.description,
      userName: log.userName || '',
      userEmail: log.userEmail || '',
      ipAddress: log.ipAddress || '',
      changes: log.changes ? JSON.stringify(log.changes) : '',
      metadata: log.metadata ? JSON.stringify(log.metadata) : '',
    }));
  }

  /**
   * Get unique values for filters (actions, entity types, users)
   */
  async getFilterOptions(organizationId: string) {
    const [actions, entityTypes, users] = await Promise.all([
      this.prisma.auditLog.groupBy({
        by: ['action'],
        where: { organizationId },
        orderBy: { action: 'asc' },
      }),
      this.prisma.auditLog.groupBy({
        by: ['entityType'],
        where: { organizationId },
        orderBy: { entityType: 'asc' },
      }),
      this.prisma.auditLog.groupBy({
        by: ['userId', 'userName', 'userEmail'],
        where: { organizationId, userId: { not: null } },
        orderBy: { userName: 'asc' },
      }),
    ]);

    return {
      actions: actions.map((a) => a.action),
      entityTypes: entityTypes.map((e) => e.entityType),
      users: users.map((u) => ({
        id: u.userId,
        name: u.userName,
        email: u.userEmail,
      })),
    };
  }
}
