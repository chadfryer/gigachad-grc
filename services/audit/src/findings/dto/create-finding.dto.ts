import { IsString, IsOptional, IsDateString, IsArray, MaxLength } from 'class-validator';

export class CreateFindingDto {
  @IsString()
  organizationId: string;

  @IsString()
  auditId: string;

  @IsString()
  @MaxLength(255)
  title: string;

  @IsString()
  @MaxLength(5000)
  description: string;

  @IsString()
  category: string; // control_deficiency, documentation_gap, process_issue, compliance_gap

  @IsString()
  severity: string; // critical, high, medium, low, observation

  @IsOptional()
  @IsString()
  controlId?: string;

  @IsOptional()
  @IsString()
  requirementRef?: string;

  @IsOptional()
  @IsString()
  @MaxLength(10000)
  remediationPlan?: string;

  @IsOptional()
  @IsString()
  remediationOwner?: string;

  @IsOptional()
  @IsDateString()
  targetDate?: string;

  @IsOptional()
  @IsString()
  @MaxLength(5000)
  rootCause?: string;

  @IsOptional()
  @IsString()
  @MaxLength(5000)
  impact?: string;

  @IsOptional()
  @IsString()
  @MaxLength(10000)
  recommendation?: string;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  tags?: string[];
}
