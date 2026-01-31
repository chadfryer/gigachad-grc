import { IsString, IsOptional, IsBoolean, IsArray, IsNumber, IsEnum, Min, Max, ValidateNested } from 'class-validator';
import { Type } from 'class-transformer';

export enum ThreatActor {
  external_attacker = 'external_attacker',
  insider_malicious = 'insider_malicious',
  insider_negligent = 'insider_negligent',
  nation_state = 'nation_state',
  organized_crime = 'organized_crime',
  hacktivist = 'hacktivist',
  competitor = 'competitor',
  natural_disaster = 'natural_disaster',
}

export enum AttackVector {
  phishing = 'phishing',
  malware = 'malware',
  social_engineering = 'social_engineering',
  brute_force = 'brute_force',
  supply_chain = 'supply_chain',
  physical = 'physical',
  insider_access = 'insider_access',
  web_application = 'web_application',
  network = 'network',
  api = 'api',
}

export enum Likelihood {
  rare = 'rare',
  unlikely = 'unlikely',
  possible = 'possible',
  likely = 'likely',
  almost_certain = 'almost_certain',
}

export enum Impact {
  negligible = 'negligible',
  minor = 'minor',
  moderate = 'moderate',
  major = 'major',
  severe = 'severe',
}

export class RiskSimulationDto {
  @IsOptional()
  @IsNumber()
  @Min(0)
  @Max(100)
  controlEffectiveness?: number;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  mitigations?: string[];

  @IsOptional()
  @IsNumber()
  @Min(0)
  financialImpact?: number;

  @IsOptional()
  @IsNumber()
  @Min(0)
  recoveryTimeHours?: number;
}

export class CreateRiskScenarioDto {
  @IsString()
  title: string;

  @IsString()
  description: string;

  @IsString()
  category: string;

  @IsEnum(ThreatActor)
  threatActor: ThreatActor;

  @IsEnum(AttackVector)
  attackVector: AttackVector;

  @IsArray()
  @IsString({ each: true })
  targetAssets: string[];

  @IsEnum(Likelihood)
  likelihood: Likelihood;

  @IsEnum(Impact)
  impact: Impact;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  tags?: string[];

  @IsOptional()
  @IsBoolean()
  isTemplate?: boolean;

  @IsOptional()
  @ValidateNested()
  @Type(() => RiskSimulationDto)
  simulation?: RiskSimulationDto;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  relatedControlIds?: string[];

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  relatedRiskIds?: string[];

  @IsOptional()
  @IsString()
  mitigationStrategy?: string;

  @IsOptional()
  @IsString()
  businessContext?: string;

  @IsOptional()
  @IsString()
  complianceImpact?: string;
}

export class UpdateRiskScenarioDto {
  @IsOptional()
  @IsString()
  title?: string;

  @IsOptional()
  @IsString()
  description?: string;

  @IsOptional()
  @IsString()
  category?: string;

  @IsOptional()
  @IsEnum(ThreatActor)
  threatActor?: ThreatActor;

  @IsOptional()
  @IsEnum(AttackVector)
  attackVector?: AttackVector;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  targetAssets?: string[];

  @IsOptional()
  @IsEnum(Likelihood)
  likelihood?: Likelihood;

  @IsOptional()
  @IsEnum(Impact)
  impact?: Impact;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  tags?: string[];

  @IsOptional()
  @IsBoolean()
  isTemplate?: boolean;

  @IsOptional()
  @ValidateNested()
  @Type(() => RiskSimulationDto)
  simulation?: RiskSimulationDto;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  relatedControlIds?: string[];

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  relatedRiskIds?: string[];

  @IsOptional()
  @IsString()
  mitigationStrategy?: string;

  @IsOptional()
  @IsString()
  businessContext?: string;

  @IsOptional()
  @IsString()
  complianceImpact?: string;
}

export class ListRiskScenariosQueryDto {
  @IsOptional()
  @IsString()
  search?: string;

  @IsOptional()
  @IsString()
  category?: string;

  @IsOptional()
  @IsEnum(ThreatActor)
  threatActor?: ThreatActor;

  @IsOptional()
  @IsEnum(AttackVector)
  attackVector?: AttackVector;

  @IsOptional()
  @IsBoolean()
  isTemplate?: boolean;

  @IsOptional()
  @IsNumber()
  @Type(() => Number)
  page?: number;

  @IsOptional()
  @IsNumber()
  @Type(() => Number)
  limit?: number;
}

export class CloneScenarioDto {
  @IsOptional()
  @IsString()
  newTitle?: string;
}

export class BulkCreateScenarioDto {
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => CreateRiskScenarioDto)
  scenarios: CreateRiskScenarioDto[];
}




