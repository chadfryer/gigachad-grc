import { Injectable, Logger, NotFoundException, BadRequestException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import * as crypto from 'crypto';
import {
  CreateExportJobDto,
  ExportJobDto,
  ExportJobListQueryDto,
  ExportFormat,
  ExportEntityType,
  ExportStatus,
} from './dto/export.dto';
import { 
  parsePaginationParams, 
  createPaginatedResponse,
} from '@gigachad-grc/shared';

interface ExportJobRecord {
  id: string;
  organizationId: string;
  entityType: ExportEntityType;
  format: ExportFormat;
  status: ExportStatus;
  filters?: Record<string, any>;
  fields?: string[];
  includeRelations: boolean;
  fileName?: string;
  fileSize?: number;
  fileContent?: string; // Base64 encoded for in-memory storage
  expiresAt?: Date;
  errorMessage?: string;
  recordCount?: number;
  requestedBy: string;
  createdAt: Date;
  completedAt?: Date;
}

// In-memory store for export jobs
const exportJobStore = new Map<string, ExportJobRecord>();

// Cleanup expired jobs every hour
setInterval(() => {
  const now = new Date();
  for (const [id, job] of exportJobStore.entries()) {
    if (job.expiresAt && job.expiresAt < now) {
      exportJobStore.delete(id);
    }
  }
}, 60 * 60 * 1000);

@Injectable()
export class ExportsService {
  private readonly logger = new Logger(ExportsService.name);

  constructor(private readonly prisma: PrismaService) {}

  async createExportJob(
    organizationId: string,
    userId: string,
    dto: CreateExportJobDto,
  ): Promise<ExportJobDto> {
    const id = crypto.randomUUID();
    const now = new Date();

    const job: ExportJobRecord = {
      id,
      organizationId,
      entityType: dto.entityType,
      format: dto.format || ExportFormat.JSON,
      status: ExportStatus.PENDING,
      filters: dto.filters,
      fields: dto.fields,
      includeRelations: dto.includeRelations || false,
      requestedBy: userId,
      createdAt: now,
    };

    exportJobStore.set(id, job);
    this.logger.log(`Created export job ${id} for ${dto.entityType}`);

    // Process asynchronously
    this.processExportJob(id).catch(err => {
      this.logger.error(`Export job ${id} failed: ${err.message}`);
    });

    return this.toDto(job);
  }

  async getExportJob(organizationId: string, id: string): Promise<ExportJobDto> {
    const job = exportJobStore.get(id);
    if (!job || job.organizationId !== organizationId) {
      throw new NotFoundException(`Export job ${id} not found`);
    }
    return this.toDto(job);
  }

  async listExportJobs(
    organizationId: string,
    query: ExportJobListQueryDto,
  ) {
    const pagination = parsePaginationParams({
      page: query.page,
      limit: query.limit,
    });

    let jobs = Array.from(exportJobStore.values())
      .filter(j => j.organizationId === organizationId);

    if (query.status) {
      jobs = jobs.filter(j => j.status === query.status);
    }

    if (query.entityType) {
      jobs = jobs.filter(j => j.entityType === query.entityType);
    }

    jobs.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());

    const total = jobs.length;
    const offset = (pagination.page - 1) * pagination.limit;
    const paginatedJobs = jobs.slice(offset, offset + pagination.limit);

    return createPaginatedResponse(
      paginatedJobs.map(j => this.toDto(j)),
      total,
      pagination,
    );
  }

  async downloadExport(
    organizationId: string,
    id: string,
  ): Promise<{ content: string; contentType: string; fileName: string }> {
    const job = exportJobStore.get(id);
    if (!job || job.organizationId !== organizationId) {
      throw new NotFoundException(`Export job ${id} not found`);
    }

    if (job.status !== ExportStatus.COMPLETED) {
      throw new BadRequestException(`Export job is not completed (status: ${job.status})`);
    }

    if (job.expiresAt && job.expiresAt < new Date()) {
      throw new BadRequestException('Export has expired');
    }

    const contentType = this.getContentType(job.format);
    
    return {
      content: job.fileContent || '',
      contentType,
      fileName: job.fileName || `export.${job.format}`,
    };
  }

  async cancelExportJob(organizationId: string, id: string): Promise<void> {
    const job = exportJobStore.get(id);
    if (!job || job.organizationId !== organizationId) {
      throw new NotFoundException(`Export job ${id} not found`);
    }

    if (job.status === ExportStatus.COMPLETED) {
      throw new BadRequestException('Cannot cancel completed export');
    }

    job.status = ExportStatus.FAILED;
    job.errorMessage = 'Cancelled by user';
    exportJobStore.set(id, job);
  }

  /**
   * Process an export job by ID
   * Can be called by the job scheduler for async processing
   */
  async processExportJob(id: string, _organizationId?: string): Promise<void> {
    const job = exportJobStore.get(id);
    if (!job) return;

    try {
      job.status = ExportStatus.PROCESSING;
      exportJobStore.set(id, job);

      const data = await this.fetchData(job);
      const content = await this.formatData(data, job.format);

      job.status = ExportStatus.COMPLETED;
      job.fileContent = Buffer.from(content).toString('base64');
      job.fileName = `${job.entityType}_export_${new Date().toISOString().split('T')[0]}.${job.format}`;
      job.fileSize = content.length;
      job.recordCount = Array.isArray(data) ? data.length : 1;
      job.completedAt = new Date();
      job.expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hour expiry

      exportJobStore.set(id, job);
      this.logger.log(`Export job ${id} completed: ${job.recordCount} records`);
    } catch (error) {
      job.status = ExportStatus.FAILED;
      job.errorMessage = error.message;
      exportJobStore.set(id, job);
      throw error;
    }
  }

  private async fetchData(job: ExportJobRecord): Promise<any[]> {
    const { organizationId, entityType, filters, includeRelations } = job;

    switch (entityType) {
      case ExportEntityType.Controls:
        return this.prisma.control.findMany({
          where: {
            OR: [
              { organizationId: null },
              { organizationId },
            ],
            deletedAt: null,
            ...filters,
          },
          include: includeRelations ? {
            implementations: { where: { organizationId } },
            mappings: true,
          } : undefined,
        });

      case ExportEntityType.Policies:
        return this.prisma.policy.findMany({
          where: { organizationId, deletedAt: null, ...filters },
          include: includeRelations ? {
            versions: true,
            controlLinks: true,
          } : undefined,
        });

      case ExportEntityType.Risks:
        return this.prisma.risk.findMany({
          where: { organizationId, deletedAt: null, ...filters },
          include: includeRelations ? {
            controls: true,
            assessment: true,
          } : undefined,
        });

      case ExportEntityType.Evidence:
        return this.prisma.evidence.findMany({
          where: { organizationId, deletedAt: null, ...filters },
          include: includeRelations ? {
            controlLinks: true,
          } : undefined,
        });

      case ExportEntityType.Tasks:
        return this.prisma.task.findMany({
          where: { organizationId, ...filters },
          include: includeRelations ? {
            assignee: { select: { id: true, displayName: true, email: true } },
          } : undefined,
        });

      case ExportEntityType.AuditLogs:
        return this.prisma.auditLog.findMany({
          where: { organizationId, ...filters },
          orderBy: { timestamp: 'desc' },
          take: 10000, // Limit audit log exports
        });

      case ExportEntityType.Users:
        return this.prisma.user.findMany({
          where: { organizationId, ...filters },
          select: {
            id: true,
            email: true,
            displayName: true,
            role: true,
            status: true,
            lastLoginAt: true,
            createdAt: true,
          },
        });

      case ExportEntityType.Frameworks:
        return this.prisma.framework.findMany({
          where: {
            OR: [
              { organizationId: null },
              { organizationId },
            ],
            ...filters,
          },
          include: includeRelations ? {
            requirements: true,
          } : undefined,
        });

      case ExportEntityType.FullOrg:
        const [controls, policies, risks, evidence] = await Promise.all([
          this.prisma.control.findMany({
            where: { OR: [{ organizationId: null }, { organizationId }], deletedAt: null },
          }),
          this.prisma.policy.findMany({
            where: { organizationId, deletedAt: null },
          }),
          this.prisma.risk.findMany({
            where: { organizationId, deletedAt: null },
          }),
          this.prisma.evidence.findMany({
            where: { organizationId, deletedAt: null },
          }),
        ]);
        return [{ controls, policies, risks, evidence }];

      default:
        throw new Error(`Unsupported entity type: ${entityType}`);
    }
  }

  private async formatData(data: any[], format: ExportFormat): Promise<string> {
    switch (format) {
      case ExportFormat.JSON:
        return JSON.stringify(data, null, 2);

      case ExportFormat.CSV:
        if (data.length === 0) return '';
        const headers = Object.keys(data[0]);
        const rows = data.map(row => 
          headers.map(h => {
            const val = row[h];
            if (val === null || val === undefined) return '';
            if (typeof val === 'object') return JSON.stringify(val);
            return String(val).includes(',') ? `"${val}"` : val;
          }).join(',')
        );
        return [headers.join(','), ...rows].join('\n');

      case ExportFormat.XLSX:
        // For XLSX, we'd use a library like xlsx
        // For now, return JSON with xlsx extension
        return JSON.stringify(data, null, 2);

      case ExportFormat.PDF:
        // For PDF, we'd use a library like pdfkit
        // For now, return JSON with note
        return JSON.stringify({ note: 'PDF export not fully implemented', data }, null, 2);

      default:
        return JSON.stringify(data, null, 2);
    }
  }

  private getContentType(format: ExportFormat): string {
    switch (format) {
      case ExportFormat.JSON:
        return 'application/json';
      case ExportFormat.CSV:
        return 'text/csv';
      case ExportFormat.XLSX:
        return 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
      case ExportFormat.PDF:
        return 'application/pdf';
      default:
        return 'application/octet-stream';
    }
  }

  private toDto(job: ExportJobRecord): ExportJobDto {
    return {
      id: job.id,
      entityType: job.entityType,
      format: job.format,
      status: job.status,
      fileName: job.fileName,
      fileSize: job.fileSize,
      downloadUrl: job.status === ExportStatus.COMPLETED ? `/api/exports/${job.id}/download` : undefined,
      expiresAt: job.expiresAt,
      errorMessage: job.errorMessage,
      recordCount: job.recordCount,
      requestedBy: job.requestedBy,
      createdAt: job.createdAt,
      completedAt: job.completedAt,
    };
  }
}
