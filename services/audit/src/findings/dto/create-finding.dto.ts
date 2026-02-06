import { IsString, IsOptional, IsDateString, IsArray, IsEnum } from 'class-validator';

// Security: Enum validation prevents injection of arbitrary values
export enum FindingSeverity {
  CRITICAL = 'critical',
  HIGH = 'high',
  MEDIUM = 'medium',
  LOW = 'low',
  OBSERVATION = 'observation',
}

export enum FindingCategory {
  CONTROL_DEFICIENCY = 'control_deficiency',
  DOCUMENTATION_GAP = 'documentation_gap',
  PROCESS_ISSUE = 'process_issue',
  COMPLIANCE_GAP = 'compliance_gap',
}

export class CreateFindingDto {
  @IsOptional()
  @IsString()
  organizationId?: string;

  @IsString()
  auditId: string;

  @IsString()
  title: string;

  @IsString()
  description: string;

  @IsEnum(FindingCategory, { message: 'category must be a valid finding category' })
  category: FindingCategory;

  @IsEnum(FindingSeverity, { message: 'severity must be a valid severity level' })
  severity: FindingSeverity;

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
  @IsString()
  rootCause?: string;

  @IsOptional()
  @IsString()
  impact?: string;

  @IsOptional()
  @IsString()
  recommendation?: string;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  tags?: string[];
}
