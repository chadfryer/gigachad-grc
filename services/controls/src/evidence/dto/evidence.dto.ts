import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsString,
  IsNotEmpty,
  IsOptional,
  IsArray,
  IsEnum,
  IsUUID,
  IsDateString,
  MaxLength,
} from 'class-validator';

export enum EvidenceType {
  SCREENSHOT = 'screenshot',
  DOCUMENT = 'document',
  EXPORT = 'export',
  REPORT = 'report',
  CONFIGURATION = 'configuration',
  LOG = 'log',
  POLICY = 'policy',
  AUTOMATED = 'automated',
  OTHER = 'other',
}

export enum EvidenceSource {
  MANUAL = 'manual',
  AWS = 'aws',
  GCP = 'gcp',
  AZURE = 'azure',
  GITHUB = 'github',
  OKTA = 'okta',
  JIRA = 'jira',
  API = 'api',
  WEBHOOK = 'webhook',
}

export enum EvidenceStatus {
  PENDING_REVIEW = 'pending_review',
  APPROVED = 'approved',
  REJECTED = 'rejected',
  EXPIRED = 'expired',
}

export class UploadEvidenceDto {
  @ApiProperty({ example: 'MFA Configuration Screenshot' })
  @IsString()
  @IsNotEmpty()
  @MaxLength(255)
  title: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  @MaxLength(5000)
  description?: string;

  @ApiProperty({ enum: EvidenceType, example: EvidenceType.SCREENSHOT })
  @IsEnum(EvidenceType)
  type: EvidenceType;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  @MaxLength(100)
  category?: string;

  @ApiPropertyOptional({ type: [String] })
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  tags?: string[];

  @ApiPropertyOptional()
  @IsOptional()
  @IsDateString()
  validFrom?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsDateString()
  validUntil?: string;

  @ApiPropertyOptional({ type: [String], description: 'Control IDs to link' })
  @IsOptional()
  @IsArray()
  @IsUUID('4', { each: true })
  controlIds?: string[];

  @ApiPropertyOptional()
  @IsOptional()
  @IsUUID()
  folderId?: string;
}

export class UpdateEvidenceDto {
  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  @MaxLength(255)
  title?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  @MaxLength(5000)
  description?: string;

  @ApiPropertyOptional({ enum: EvidenceType })
  @IsOptional()
  @IsEnum(EvidenceType)
  type?: EvidenceType;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  @MaxLength(100)
  category?: string;

  @ApiPropertyOptional({ type: [String] })
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  tags?: string[];

  @ApiPropertyOptional()
  @IsOptional()
  @IsDateString()
  validUntil?: string;
}

export class ReviewEvidenceDto {
  @ApiProperty({ enum: ['approved', 'rejected'] })
  @IsEnum(['approved', 'rejected'])
  status: 'approved' | 'rejected';

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  @MaxLength(5000)
  notes?: string;
}

export class LinkEvidenceDto {
  @ApiProperty({ type: [String] })
  @IsArray()
  @IsUUID('4', { each: true })
  controlIds: string[];

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  @MaxLength(5000)
  notes?: string;
}

export class CreateFolderDto {
  @ApiProperty()
  @IsString()
  @IsNotEmpty()
  @MaxLength(100)
  name: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsUUID()
  parentId?: string;
}

export class EvidenceFilterDto {
  @ApiPropertyOptional({ enum: EvidenceType, isArray: true })
  @IsOptional()
  @IsArray()
  type?: EvidenceType[];

  @ApiPropertyOptional({ enum: EvidenceSource, isArray: true })
  @IsOptional()
  @IsArray()
  source?: EvidenceSource[];

  @ApiPropertyOptional({ enum: EvidenceStatus, isArray: true })
  @IsOptional()
  @IsArray()
  status?: EvidenceStatus[];

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  category?: string;

  @ApiPropertyOptional({ type: [String] })
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  tags?: string[];

  @ApiPropertyOptional()
  @IsOptional()
  @IsUUID()
  controlId?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsUUID()
  folderId?: string;

  @ApiPropertyOptional({ description: 'Filter by workspace ID (multi-workspace mode)' })
  @IsOptional()
  @IsUUID()
  workspaceId?: string;

  @ApiPropertyOptional()
  @IsOptional()
  expiringSoon?: boolean;

  @ApiPropertyOptional()
  @IsOptional()
  expired?: boolean;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  search?: string;

  @ApiPropertyOptional({ default: 1 })
  @IsOptional()
  page?: number;

  @ApiPropertyOptional({ default: 20 })
  @IsOptional()
  limit?: number;

  @ApiPropertyOptional({ default: 'createdAt' })
  @IsOptional()
  @IsString()
  sortBy?: string;

  @ApiPropertyOptional({ enum: ['asc', 'desc'], default: 'desc' })
  @IsOptional()
  sortOrder?: 'asc' | 'desc';
}
