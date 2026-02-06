import { IsString, IsOptional, IsDateString, IsArray, IsEnum } from 'class-validator';
import { FindingSeverity, FindingCategory } from './create-finding.dto';

// Security: Enum validation for finding status prevents arbitrary value injection
export enum FindingStatus {
  OPEN = 'open',
  ACKNOWLEDGED = 'acknowledged',
  REMEDIATION_PLANNED = 'remediation_planned',
  REMEDIATION_IN_PROGRESS = 'remediation_in_progress',
  RESOLVED = 'resolved',
  ACCEPTED_RISK = 'accepted_risk',
}

export class UpdateFindingDto {
  @IsOptional()
  @IsString()
  title?: string;

  @IsOptional()
  @IsString()
  description?: string;

  @IsOptional()
  @IsEnum(FindingCategory, { message: 'category must be a valid finding category' })
  category?: FindingCategory;

  @IsOptional()
  @IsEnum(FindingSeverity, { message: 'severity must be a valid severity level' })
  severity?: FindingSeverity;

  @IsOptional()
  @IsEnum(FindingStatus, { message: 'status must be a valid finding status' })
  status?: FindingStatus;

  @IsOptional()
  @IsString()
  controlId?: string;

  @IsOptional()
  @IsString()
  requirementRef?: string;

  @IsOptional()
  @IsString()
  remediationPlan?: string;

  @IsOptional()
  @IsString()
  remediationOwner?: string;

  @IsOptional()
  @IsDateString()
  targetDate?: string;

  @IsOptional()
  @IsDateString()
  actualDate?: string;

  @IsOptional()
  @IsString()
  rootCause?: string;

  @IsOptional()
  @IsString()
  impact?: string;

  @IsOptional()
  @IsString()
  recommendation?: string;

  @IsOptional()
  @IsString()
  managementResponse?: string;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  tags?: string[];
}
