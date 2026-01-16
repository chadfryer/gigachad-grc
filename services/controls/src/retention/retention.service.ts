import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import * as crypto from 'crypto';
import {
  CreateRetentionPolicyDto,
  UpdateRetentionPolicyDto,
  RetentionPolicyDto,
  RetentionPolicyListQueryDto,
  RunRetentionPolicyDto,
  RetentionRunResultDto,
  RetentionEntityType,
  RetentionAction,
  RetentionPolicyStatus,
} from './dto/retention.dto';
import { 
  parsePaginationParams, 
  createPaginatedResponse,
} from '@gigachad-grc/shared';

interface RetentionPolicyRecord {
  id: string;
  organizationId: string;
  name: string;
  description?: string;
  entityType: RetentionEntityType;
  retentionDays: number;
  action: RetentionAction;
  status: RetentionPolicyStatus;
  lastRunAt?: Date;
  nextRunAt?: Date;
  lastRunRecordsProcessed?: number;
  createdBy: string;
  createdAt: Date;
  updatedAt: Date;
}

// In-memory store
const policyStore = new Map<string, RetentionPolicyRecord>();

@Injectable()
export class RetentionService {
  private readonly logger = new Logger(RetentionService.name);

  constructor(private readonly prisma: PrismaService) {}

  async createPolicy(
    organizationId: string,
    userId: string,
    dto: CreateRetentionPolicyDto,
  ): Promise<RetentionPolicyDto> {
    const id = crypto.randomUUID();
    const now = new Date();

    const policy: RetentionPolicyRecord = {
      id,
      organizationId,
      name: dto.name,
      description: dto.description,
      entityType: dto.entityType,
      retentionDays: dto.retentionDays,
      action: dto.action || RetentionAction.ARCHIVE,
      status: dto.status || RetentionPolicyStatus.DRAFT,
      createdBy: userId,
      createdAt: now,
      updatedAt: now,
    };

    // Calculate next run (daily at midnight)
    if (policy.status === RetentionPolicyStatus.ACTIVE) {
      const tomorrow = new Date(now);
      tomorrow.setDate(tomorrow.getDate() + 1);
      tomorrow.setHours(0, 0, 0, 0);
      policy.nextRunAt = tomorrow;
    }

    policyStore.set(id, policy);
    this.logger.log(`Created retention policy ${id} for ${dto.entityType}`);

    return this.toDto(policy);
  }

  async updatePolicy(
    organizationId: string,
    policyId: string,
    dto: UpdateRetentionPolicyDto,
  ): Promise<RetentionPolicyDto> {
    const policy = policyStore.get(policyId);
    if (!policy || policy.organizationId !== organizationId) {
      throw new NotFoundException(`Retention policy ${policyId} not found`);
    }

    const updated: RetentionPolicyRecord = {
      ...policy,
      name: dto.name ?? policy.name,
      description: dto.description ?? policy.description,
      retentionDays: dto.retentionDays ?? policy.retentionDays,
      action: dto.action ?? policy.action,
      status: dto.status ?? policy.status,
      updatedAt: new Date(),
    };

    // Update next run if activating
    if (dto.status === RetentionPolicyStatus.ACTIVE && policy.status !== RetentionPolicyStatus.ACTIVE) {
      const tomorrow = new Date();
      tomorrow.setDate(tomorrow.getDate() + 1);
      tomorrow.setHours(0, 0, 0, 0);
      updated.nextRunAt = tomorrow;
    } else if (dto.status === RetentionPolicyStatus.INACTIVE || dto.status === RetentionPolicyStatus.DRAFT) {
      updated.nextRunAt = undefined;
    }

    policyStore.set(policyId, updated);
    return this.toDto(updated);
  }

  async deletePolicy(organizationId: string, policyId: string): Promise<void> {
    const policy = policyStore.get(policyId);
    if (!policy || policy.organizationId !== organizationId) {
      throw new NotFoundException(`Retention policy ${policyId} not found`);
    }

    policyStore.delete(policyId);
    this.logger.log(`Deleted retention policy ${policyId}`);
  }

  async getPolicy(organizationId: string, policyId: string): Promise<RetentionPolicyDto> {
    const policy = policyStore.get(policyId);
    if (!policy || policy.organizationId !== organizationId) {
      throw new NotFoundException(`Retention policy ${policyId} not found`);
    }
    return this.toDto(policy);
  }

  async listPolicies(
    organizationId: string,
    query: RetentionPolicyListQueryDto,
  ) {
    const pagination = parsePaginationParams({
      page: query.page,
      limit: query.limit,
    });

    let policies = Array.from(policyStore.values())
      .filter(p => p.organizationId === organizationId);

    if (query.entityType) {
      policies = policies.filter(p => p.entityType === query.entityType);
    }

    if (query.status) {
      policies = policies.filter(p => p.status === query.status);
    }

    policies.sort((a, b) => a.name.localeCompare(b.name));

    const total = policies.length;
    const offset = (pagination.page - 1) * pagination.limit;
    const paginatedPolicies = policies.slice(offset, offset + pagination.limit);

    return createPaginatedResponse(
      paginatedPolicies.map(p => this.toDto(p)),
      total,
      pagination,
    );
  }

  async runPolicy(
    organizationId: string,
    policyId: string,
    dto: RunRetentionPolicyDto,
  ): Promise<RetentionRunResultDto> {
    const policy = policyStore.get(policyId);
    if (!policy || policy.organizationId !== organizationId) {
      throw new NotFoundException(`Retention policy ${policyId} not found`);
    }

    const dryRun = dto.dryRun !== false;
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - policy.retentionDays);

    let recordsFound = 0;
    let recordsProcessed = 0;

    try {
      switch (policy.entityType) {
        case RetentionEntityType.AUDIT_LOGS:
          const auditCount = await this.prisma.auditLog.count({
            where: {
              organizationId,
              timestamp: { lt: cutoffDate },
            },
          });
          recordsFound = auditCount;

          if (!dryRun && policy.action === RetentionAction.DELETE) {
            const result = await this.prisma.auditLog.deleteMany({
              where: {
                organizationId,
                timestamp: { lt: cutoffDate },
              },
            });
            recordsProcessed = result.count;
          } else {
            recordsProcessed = recordsFound;
          }
          break;

        case RetentionEntityType.NOTIFICATIONS:
          const notifCount = await this.prisma.notification.count({
            where: {
              organizationId,
              createdAt: { lt: cutoffDate },
            },
          });
          recordsFound = notifCount;

          if (!dryRun && policy.action === RetentionAction.DELETE) {
            const result = await this.prisma.notification.deleteMany({
              where: {
                organizationId,
                createdAt: { lt: cutoffDate },
              },
            });
            recordsProcessed = result.count;
          } else {
            recordsProcessed = recordsFound;
          }
          break;

        case RetentionEntityType.TASKS:
          const taskCount = await this.prisma.task.count({
            where: {
              organizationId,
              status: 'completed',
              completedAt: { lt: cutoffDate },
            },
          });
          recordsFound = taskCount;

          if (!dryRun) {
            if (policy.action === RetentionAction.DELETE) {
              const result = await this.prisma.task.deleteMany({
                where: {
                  organizationId,
                  status: 'completed',
                  completedAt: { lt: cutoffDate },
                },
              });
              recordsProcessed = result.count;
            } else {
              // Archive - mark as archived for archival (Task doesn't have deletedAt)
              const result = await this.prisma.task.updateMany({
                where: {
                  organizationId,
                  status: 'completed',
                  completedAt: { lt: cutoffDate },
                },
                data: {
                  status: 'archived',
                },
              });
              recordsProcessed = result.count;
            }
          } else {
            recordsProcessed = recordsFound;
          }
          break;

        case RetentionEntityType.EVIDENCE:
          // Handle evidence retention - only process expired or rejected evidence
          const evidenceCount = await this.prisma.evidence.count({
            where: {
              organizationId,
              createdAt: { lt: cutoffDate },
              deletedAt: null, // Not already soft-deleted
              // Only process evidence that's expired, rejected, or past validUntil
              OR: [
                { status: 'expired' },
                { status: 'rejected' },
                { isExpired: true },
                { validUntil: { lt: cutoffDate } },
              ],
            },
          });
          recordsFound = evidenceCount;

          if (!dryRun) {
            if (policy.action === RetentionAction.DELETE) {
              // Soft delete by setting deletedAt
              const result = await this.prisma.evidence.updateMany({
                where: {
                  organizationId,
                  createdAt: { lt: cutoffDate },
                  deletedAt: null,
                  OR: [
                    { status: 'expired' },
                    { status: 'rejected' },
                    { isExpired: true },
                    { validUntil: { lt: cutoffDate } },
                  ],
                },
                data: {
                  deletedAt: new Date(),
                },
              });
              recordsProcessed = result.count;
            } else {
              // Archive - mark as expired (closest to archive in the schema)
              const result = await this.prisma.evidence.updateMany({
                where: {
                  organizationId,
                  createdAt: { lt: cutoffDate },
                  deletedAt: null,
                  OR: [
                    { status: 'expired' },
                    { status: 'rejected' },
                    { isExpired: true },
                    { validUntil: { lt: cutoffDate } },
                  ],
                },
                data: {
                  status: 'expired',
                  isExpired: true,
                },
              });
              recordsProcessed = result.count;
            }
          } else {
            recordsProcessed = recordsFound;
          }
          break;

        case RetentionEntityType.POLICY_VERSIONS:
          // Handle policy version retention - delete old versions beyond retention period
          // Keep the most recent version for each policy
          
          // Get all policies in this organization
          const orgPolicies = await this.prisma.policy.findMany({
            where: { organizationId },
            select: { id: true },
          });

          // Build list of version IDs that should be protected (most recent per policy)
          const protectedVersions = new Set<string>();
          for (const p of orgPolicies) {
            // Find the most recent version for this policy
            const latestVersion = await this.prisma.policyVersion.findFirst({
              where: { policyId: p.id },
              orderBy: { createdAt: 'desc' },
              select: { id: true },
            });
            if (latestVersion) {
              protectedVersions.add(latestVersion.id);
            }
          }

          // Count old versions that are not the latest
          const allOldVersions = await this.prisma.policyVersion.findMany({
            where: {
              policy: { organizationId },
              createdAt: { lt: cutoffDate },
            },
            select: { id: true },
          });
          
          const versionsToDelete = allOldVersions.filter(v => !protectedVersions.has(v.id));
          recordsFound = versionsToDelete.length;

          if (!dryRun && policy.action === RetentionAction.DELETE && versionsToDelete.length > 0) {
            // Delete old policy versions (not the most recent)
            const result = await this.prisma.policyVersion.deleteMany({
              where: {
                id: { in: versionsToDelete.map(v => v.id) },
              },
            });
            recordsProcessed = result.count;
          } else {
            // Archive not applicable for versions - they don't have archive status
            recordsProcessed = recordsFound;
          }
          break;

        case RetentionEntityType.EXPORT_JOBS:
          // Handle export job retention - clean up old export jobs and their files
          // Use raw SQL since ExportJob might be in-memory only
          try {
            // Check if the table exists
            const exportJobCount = await this.prisma.$queryRaw<[{ count: bigint }]>`
              SELECT COUNT(*) as count FROM export_jobs 
              WHERE organization_id = ${organizationId}
              AND created_at < ${cutoffDate}
            `;
            recordsFound = Number(exportJobCount[0]?.count || 0);

            if (!dryRun && policy.action === RetentionAction.DELETE) {
              const result = await this.prisma.$executeRaw`
                DELETE FROM export_jobs 
                WHERE organization_id = ${organizationId}
                AND created_at < ${cutoffDate}
              `;
              recordsProcessed = result;
            } else {
              recordsProcessed = recordsFound;
            }
          } catch (error) {
            // Export jobs might be stored in memory only
            this.logger.warn('Export jobs table not found - exports may be stored in memory only');
            recordsFound = 0;
            recordsProcessed = 0;
          }
          break;

        default:
          this.logger.warn(`Retention for ${policy.entityType} not supported`);
          recordsFound = 0;
          recordsProcessed = 0;
      }

      // Update policy run info
      if (!dryRun) {
        policy.lastRunAt = new Date();
        policy.lastRunRecordsProcessed = recordsProcessed;

        // Schedule next run
        const tomorrow = new Date();
        tomorrow.setDate(tomorrow.getDate() + 1);
        tomorrow.setHours(0, 0, 0, 0);
        policy.nextRunAt = tomorrow;
        policy.updatedAt = new Date();

        policyStore.set(policyId, policy);
      }

      this.logger.log(
        `Retention policy ${policyId} ${dryRun ? '(dry run)' : ''}: ` +
        `found ${recordsFound}, processed ${recordsProcessed}`
      );

      return {
        policyId: policy.id,
        policyName: policy.name,
        entityType: policy.entityType,
        action: policy.action,
        recordsFound,
        recordsProcessed,
        dryRun,
        executedAt: new Date(),
      };
    } catch (error) {
      this.logger.error(`Retention policy ${policyId} failed: ${error.message}`);
      return {
        policyId: policy.id,
        policyName: policy.name,
        entityType: policy.entityType,
        action: policy.action,
        recordsFound,
        recordsProcessed: 0,
        dryRun,
        executedAt: new Date(),
        error: error.message,
      };
    }
  }

  private toDto(policy: RetentionPolicyRecord): RetentionPolicyDto {
    return {
      id: policy.id,
      name: policy.name,
      description: policy.description,
      entityType: policy.entityType,
      retentionDays: policy.retentionDays,
      action: policy.action,
      status: policy.status,
      lastRunAt: policy.lastRunAt,
      nextRunAt: policy.nextRunAt,
      lastRunRecordsProcessed: policy.lastRunRecordsProcessed,
      createdBy: policy.createdBy,
      createdAt: policy.createdAt,
      updatedAt: policy.updatedAt,
    };
  }
}
