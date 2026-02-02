import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsString, IsOptional, IsDateString, IsNumber, Min, IsIn, MaxLength } from 'class-validator';
import { Type, Transform } from 'class-transformer';

// Sanitization helper - strips HTML and trims
const sanitizeString = ({ value }: { value: unknown }) => {
  if (typeof value === 'string') {
    return value.trim().replace(/<[^>]*>/g, '');
  }
  return value;
};

export class CreateAuditLogDto {
  @ApiProperty()
  @IsString()
  @MaxLength(100)
  @Transform(sanitizeString)
  action: string;

  @ApiProperty()
  @IsString()
  @MaxLength(100)
  @Transform(sanitizeString)
  entityType: string;

  @ApiProperty()
  @IsString()
  @MaxLength(255)
  @Transform(sanitizeString)
  entityId: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  @MaxLength(500)
  @Transform(sanitizeString)
  entityName?: string;

  @ApiProperty()
  @IsString()
  @MaxLength(2000)
  @Transform(sanitizeString)
  description: string;

  @ApiPropertyOptional()
  @IsOptional()
  changes?: Record<string, unknown>;

  @ApiPropertyOptional()
  @IsOptional()
  metadata?: Record<string, unknown>;
}

export class AuditLogFilterDto {
  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  @MaxLength(100)
  @Transform(sanitizeString)
  entityType?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  @MaxLength(255)
  @Transform(sanitizeString)
  entityId?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  @MaxLength(100)
  @Transform(sanitizeString)
  action?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  @MaxLength(255)
  @Transform(sanitizeString)
  userId?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  @MaxLength(500)
  @Transform(sanitizeString)
  search?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsDateString()
  startDate?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsDateString()
  endDate?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  @Min(1)
  page?: number;

  @ApiPropertyOptional()
  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  @Min(1)
  limit?: number;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  @IsIn(['timestamp', 'action', 'entityType', 'userName'])
  sortBy?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  @IsIn(['asc', 'desc'])
  sortOrder?: 'asc' | 'desc';
}

export class AuditLogResponseDto {
  @ApiProperty()
  id: string;

  @ApiProperty()
  organizationId: string;

  @ApiPropertyOptional()
  userId?: string;

  @ApiPropertyOptional()
  userEmail?: string;

  @ApiPropertyOptional()
  userName?: string;

  @ApiProperty()
  action: string;

  @ApiProperty()
  entityType: string;

  @ApiProperty()
  entityId: string;

  @ApiPropertyOptional()
  entityName?: string;

  @ApiProperty()
  description: string;

  @ApiPropertyOptional()
  changes?: Record<string, unknown>;

  @ApiPropertyOptional()
  metadata?: Record<string, unknown>;

  @ApiPropertyOptional()
  ipAddress?: string;

  @ApiPropertyOptional()
  userAgent?: string;

  @ApiProperty()
  timestamp: Date;
}

// Entity types for filtering
export const ENTITY_TYPES = [
  'control',
  'evidence',
  'policy',
  'framework',
  'integration',
  'task',
  'comment',
  'requirement',
  'mapping',
  'user',
] as const;

// Action types for filtering
export const ACTION_TYPES = [
  'created',
  'updated',
  'deleted',
  'status_changed',
  'linked',
  'unlinked',
  'approved',
  'rejected',
  'uploaded',
  'downloaded',
  'reviewed',
  'synced',
  'tested',
  'completed',
  'resolved',
  'login',
  'logout',
] as const;

export type EntityType = (typeof ENTITY_TYPES)[number];
export type ActionType = (typeof ACTION_TYPES)[number];



