import { IsString, IsOptional, IsArray, IsNumber } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

// Re-export Prisma enums for convenience
export { AssetType, AssetStatus, AssetCriticality } from '@prisma/client';

export class CreateAssetDto {
  @ApiProperty()
  @IsString()
  name: string;

  @ApiPropertyOptional()
  @IsString()
  @IsOptional()
  externalId?: string;

  @ApiPropertyOptional({ default: 'manual' })
  @IsString()
  @IsOptional()
  source?: string;

  @ApiPropertyOptional({ enum: ['server', 'workstation', 'laptop', 'mobile', 'network', 'storage', 'cloud', 'application', 'database', 'other'] })
  @IsString()
  @IsOptional()
  type?: string;

  @ApiPropertyOptional()
  @IsString()
  @IsOptional()
  category?: string;

  @ApiPropertyOptional({ enum: ['active', 'inactive', 'retired', 'disposed', 'lost', 'stolen'] })
  @IsString()
  @IsOptional()
  status?: string;

  @ApiPropertyOptional({ enum: ['critical', 'high', 'medium', 'low'] })
  @IsString()
  @IsOptional()
  criticality?: string;

  @ApiPropertyOptional()
  @IsString()
  @IsOptional()
  owner?: string;

  @ApiPropertyOptional()
  @IsString()
  @IsOptional()
  location?: string;

  @ApiPropertyOptional()
  @IsString()
  @IsOptional()
  department?: string;

  @ApiPropertyOptional()
  @IsOptional()
  metadata?: Record<string, unknown>;

  @ApiPropertyOptional()
  @IsString()
  @IsOptional()
  workspaceId?: string;
}

export class UpdateAssetDto {
  @ApiPropertyOptional()
  @IsString()
  @IsOptional()
  name?: string;

  @ApiPropertyOptional()
  @IsString()
  @IsOptional()
  type?: string;

  @ApiPropertyOptional()
  @IsString()
  @IsOptional()
  category?: string;

  @ApiPropertyOptional()
  @IsString()
  @IsOptional()
  status?: string;

  @ApiPropertyOptional()
  @IsString()
  @IsOptional()
  criticality?: string;

  @ApiPropertyOptional()
  @IsString()
  @IsOptional()
  owner?: string;

  @ApiPropertyOptional()
  @IsString()
  @IsOptional()
  location?: string;

  @ApiPropertyOptional()
  @IsString()
  @IsOptional()
  department?: string;

  @ApiPropertyOptional()
  @IsOptional()
  metadata?: Record<string, unknown>;

  @ApiPropertyOptional()
  @IsString()
  @IsOptional()
  lastSyncAt?: string;
}

export class AssetFilterDto {
  @ApiPropertyOptional()
  @IsString()
  @IsOptional()
  search?: string;

  @ApiPropertyOptional({ type: [String] })
  @IsArray()
  @IsOptional()
  types?: string[];

  @ApiPropertyOptional({ type: [String] })
  @IsArray()
  @IsOptional()
  statuses?: string[];

  @ApiPropertyOptional({ type: [String] })
  @IsArray()
  @IsOptional()
  criticalities?: string[];

  @ApiPropertyOptional()
  @IsString()
  @IsOptional()
  department?: string;

  @ApiPropertyOptional()
  @IsString()
  @IsOptional()
  source?: string;

  @ApiPropertyOptional()
  @IsNumber()
  @IsOptional()
  page?: number;

  @ApiPropertyOptional()
  @IsNumber()
  @IsOptional()
  limit?: number;

  @ApiPropertyOptional()
  @IsString()
  @IsOptional()
  sortBy?: string;

  @ApiPropertyOptional()
  @IsString()
  @IsOptional()
  sortOrder?: 'asc' | 'desc';
}

export class AssetDto {
  id: string;
  externalId?: string;
  source: string;
  name: string;
  type: string;
  category?: string;
  status: string;
  criticality: string;
  owner?: string;
  location?: string;
  department?: string;
  metadata?: Record<string, unknown>;
  lastSyncAt?: Date;
  workspaceId?: string;
  workspaceName?: string;
  riskCount: number;
  linkedRisks?: Array<{
    riskId: string;
    riskCode: string;
    title: string;
  }>;
  createdAt: Date;
  updatedAt: Date;
}

export class AssetSummaryDto {
  totalAssets: number;
  byType: Array<{ type: string; count: number }>;
  byStatus: Array<{ status: string; count: number }>;
  byCriticality: Array<{ criticality: string; count: number }>;
}

export class LinkAssetToRiskDto {
  @ApiProperty()
  @IsString()
  riskId: string;

  @ApiPropertyOptional()
  @IsString()
  @IsOptional()
  impactDescription?: string;
}
