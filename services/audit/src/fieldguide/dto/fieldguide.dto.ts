import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsString, IsOptional, IsEnum, IsArray, IsObject, IsDateString } from 'class-validator';

// ============================================
// Connection DTOs
// ============================================

export class FieldGuideConnectDto {
  @ApiProperty({ description: 'FieldGuide API key' })
  @IsString()
  apiKey: string;

  @ApiPropertyOptional({ description: 'FieldGuide instance URL (if self-hosted)' })
  @IsOptional()
  @IsString()
  instanceUrl?: string;

  @ApiPropertyOptional({ description: 'Organization ID in FieldGuide' })
  @IsOptional()
  @IsString()
  fieldGuideOrgId?: string;
}

export class FieldGuideConnectionStatusDto {
  @ApiProperty({ description: 'Whether FieldGuide is connected' })
  isConnected: boolean;

  @ApiProperty({ description: 'Connection timestamp' })
  connectedAt?: Date;

  @ApiProperty({ description: 'FieldGuide organization name' })
  fieldGuideOrgName?: string;

  @ApiProperty({ description: 'Last sync timestamp' })
  lastSyncAt?: Date;

  @ApiProperty({ description: 'Sync status' })
  syncStatus: 'idle' | 'syncing' | 'error';

  @ApiPropertyOptional({ description: 'Error message if any' })
  errorMessage?: string;
}

// ============================================
// Sync DTOs
// ============================================

export enum SyncDirection {
  PULL = 'pull',     // From FieldGuide to GRC
  PUSH = 'push',     // From GRC to FieldGuide
  BIDIRECTIONAL = 'bidirectional',
}

export enum SyncEntityType {
  AUDITS = 'audits',
  REQUESTS = 'requests',
  EVIDENCE = 'evidence',
  FINDINGS = 'findings',
}

export class TriggerSyncDto {
  @ApiPropertyOptional({ description: 'Specific audit ID to sync (syncs all if not provided)' })
  @IsOptional()
  @IsString()
  auditId?: string;

  @ApiPropertyOptional({ description: 'Sync direction', enum: SyncDirection })
  @IsOptional()
  @IsEnum(SyncDirection)
  direction?: SyncDirection;

  @ApiPropertyOptional({ description: 'Entity types to sync', enum: SyncEntityType, isArray: true })
  @IsOptional()
  @IsArray()
  @IsEnum(SyncEntityType, { each: true })
  entityTypes?: SyncEntityType[];
}

export class SyncResultDto {
  @ApiProperty({ description: 'Sync ID' })
  syncId: string;

  @ApiProperty({ description: 'Sync start timestamp' })
  startedAt: Date;

  @ApiProperty({ description: 'Sync end timestamp' })
  completedAt?: Date;

  @ApiProperty({ description: 'Sync status' })
  status: 'running' | 'completed' | 'failed';

  @ApiProperty({ description: 'Entities synced' })
  entitiesSynced: {
    audits: { created: number; updated: number };
    requests: { created: number; updated: number };
    evidence: { created: number; updated: number };
    findings: { created: number; updated: number };
  };

  @ApiPropertyOptional({ description: 'Error message if failed' })
  errorMessage?: string;

  @ApiPropertyOptional({ description: 'Warnings during sync' })
  warnings?: string[];
}

export class SyncHistoryItemDto {
  @ApiProperty({ description: 'Sync ID' })
  syncId: string;

  @ApiProperty({ description: 'Sync timestamp' })
  timestamp: Date;

  @ApiProperty({ description: 'Direction' })
  direction: SyncDirection;

  @ApiProperty({ description: 'Status' })
  status: 'completed' | 'failed';

  @ApiProperty({ description: 'Duration in seconds' })
  durationSeconds: number;

  @ApiProperty({ description: 'Total entities synced' })
  totalEntities: number;
}

// ============================================
// Webhook DTOs
// ============================================

export enum FieldGuideWebhookEvent {
  AUDIT_CREATED = 'audit.created',
  AUDIT_UPDATED = 'audit.updated',
  REQUEST_CREATED = 'request.created',
  REQUEST_UPDATED = 'request.updated',
  EVIDENCE_UPLOADED = 'evidence.uploaded',
  FINDING_CREATED = 'finding.created',
  FINDING_UPDATED = 'finding.updated',
}

export class FieldGuideWebhookPayloadDto {
  @ApiProperty({ description: 'Event type' })
  @IsString()
  event: string;

  @ApiProperty({ description: 'Event timestamp' })
  @IsDateString()
  timestamp: string;

  @ApiProperty({ description: 'Event data' })
  @IsObject()
  data: Record<string, unknown>;

  @ApiProperty({ description: 'Webhook signature for verification' })
  @IsString()
  signature: string;
}

// ============================================
// Mapping DTOs
// ============================================

export class FieldGuideAuditMappingDto {
  @ApiProperty({ description: 'GRC audit ID' })
  grcAuditId: string;

  @ApiProperty({ description: 'FieldGuide audit ID' })
  fieldGuideAuditId: string;

  @ApiProperty({ description: 'Audit name' })
  name: string;

  @ApiProperty({ description: 'Sync status' })
  syncStatus: 'synced' | 'pending' | 'error';

  @ApiProperty({ description: 'Last synced at' })
  lastSyncedAt?: Date;
}

export class LinkAuditDto {
  @ApiProperty({ description: 'GRC audit ID' })
  @IsString()
  grcAuditId: string;

  @ApiProperty({ description: 'FieldGuide audit ID' })
  @IsString()
  fieldGuideAuditId: string;
}

// ============================================
// FieldGuide API Response Types
// ============================================

export interface FieldGuideAudit {
  id: string;
  name: string;
  description?: string;
  status: string;
  audit_type: string;
  framework?: string;
  start_date?: string;
  end_date?: string;
  created_at: string;
  updated_at: string;
  external_auditor?: {
    name: string;
    email: string;
    firm?: string;
  };
}

export interface FieldGuideRequest {
  id: string;
  audit_id: string;
  title: string;
  description?: string;
  status: string;
  priority: string;
  due_date?: string;
  assigned_to?: string;
  created_at: string;
  updated_at: string;
}

export interface FieldGuideEvidence {
  id: string;
  request_id: string;
  filename: string;
  file_url: string;
  file_type: string;
  uploaded_by: string;
  uploaded_at: string;
}

export interface FieldGuideFinding {
  id: string;
  audit_id: string;
  title: string;
  description: string;
  severity: string;
  status: string;
  recommendation?: string;
  management_response?: string;
  due_date?: string;
  created_at: string;
  updated_at: string;
}

