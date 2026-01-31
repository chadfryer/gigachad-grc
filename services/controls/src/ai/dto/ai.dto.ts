import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsString, IsOptional, IsEnum, IsBoolean, IsNumber, IsArray, Min, Max } from 'class-validator';

// ============================================
// AI Provider & Model Enums
// ============================================

export enum AIProvider {
  OPENAI = 'openai',
  ANTHROPIC = 'anthropic',
  MOCK = 'mock',
}

export enum OpenAIModel {
  GPT4O = 'gpt-4o',
  GPT4O_MINI = 'gpt-4o-mini',
  GPT4_TURBO = 'gpt-4-turbo',
  O1 = 'o1',
  O1_MINI = 'o1-mini',
}

export enum AnthropicModel {
  CLAUDE_3_5_SONNET = 'claude-3-5-sonnet-20241022',
  CLAUDE_3_5_HAIKU = 'claude-3-5-haiku-20241022',
  CLAUDE_3_OPUS = 'claude-3-opus-20240229',
  CLAUDE_3_SONNET = 'claude-3-sonnet-20240229',
}

// ============================================
// AI Configuration DTOs
// ============================================

export class AIConfigDto {
  @ApiProperty({ enum: AIProvider, description: 'AI provider to use' })
  @IsEnum(AIProvider)
  provider: AIProvider;

  @ApiProperty({ description: 'Model identifier' })
  @IsString()
  model: string;

  @ApiProperty({ description: 'Whether AI features are enabled' })
  @IsBoolean()
  enabled: boolean;

  @ApiPropertyOptional({ description: 'Temperature for response generation (0-2)' })
  @IsOptional()
  @IsNumber()
  @Min(0)
  @Max(2)
  temperature?: number;

  @ApiPropertyOptional({ description: 'Maximum tokens in response' })
  @IsOptional()
  @IsNumber()
  @Min(1)
  @Max(128000)
  maxTokens?: number;
}

export class UpdateAIConfigDto {
  @ApiPropertyOptional({ enum: AIProvider })
  @IsOptional()
  @IsEnum(AIProvider)
  provider?: AIProvider;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  model?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsBoolean()
  enabled?: boolean;

  @ApiPropertyOptional()
  @IsOptional()
  @IsNumber()
  @Min(0)
  @Max(2)
  temperature?: number;

  @ApiPropertyOptional()
  @IsOptional()
  @IsNumber()
  @Min(1)
  @Max(128000)
  maxTokens?: number;
}

// ============================================
// Risk Scoring DTOs
// ============================================

export class RiskScoringRequestDto {
  @ApiProperty({ description: 'Risk title' })
  @IsString()
  title: string;

  @ApiProperty({ description: 'Risk description' })
  @IsString()
  description: string;

  @ApiPropertyOptional({ description: 'Risk category' })
  @IsOptional()
  @IsString()
  category?: string;

  @ApiPropertyOptional({ description: 'Affected assets' })
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  affectedAssets?: string[];

  @ApiPropertyOptional({ description: 'Existing controls' })
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  existingControls?: string[];

  @ApiPropertyOptional({ description: 'Industry context' })
  @IsOptional()
  @IsString()
  industryContext?: string;
}

export class RiskScoringResponseDto {
  @ApiProperty({ description: 'Suggested likelihood score (1-5)' })
  likelihood: number;

  @ApiProperty({ description: 'Suggested impact score (1-5)' })
  impact: number;

  @ApiProperty({ description: 'Calculated risk score' })
  riskScore: number;

  @ApiProperty({ description: 'Risk level (Low, Medium, High, Critical)' })
  riskLevel: string;

  @ApiProperty({ description: 'Rationale for likelihood score' })
  likelihoodRationale: string;

  @ApiProperty({ description: 'Rationale for impact score' })
  impactRationale: string;

  @ApiProperty({ description: 'Suggested risk category' })
  suggestedCategory: string;

  @ApiProperty({ description: 'Recommended controls' })
  recommendedControls: string[];

  @ApiProperty({ description: 'Confidence level (0-100)' })
  confidence: number;
}

// ============================================
// Auto-Categorization DTOs
// ============================================

export enum EntityType {
  CONTROL = 'control',
  RISK = 'risk',
  POLICY = 'policy',
  EVIDENCE = 'evidence',
  VENDOR = 'vendor',
}

export class CategorizationRequestDto {
  @ApiProperty({ enum: EntityType, description: 'Type of entity to categorize' })
  @IsEnum(EntityType)
  entityType: EntityType;

  @ApiProperty({ description: 'Entity title' })
  @IsString()
  title: string;

  @ApiProperty({ description: 'Entity description' })
  @IsString()
  description: string;

  @ApiPropertyOptional({ description: 'Additional context' })
  @IsOptional()
  @IsString()
  additionalContext?: string;
}

export class CategorizationResponseDto {
  @ApiProperty({ description: 'Primary category' })
  primaryCategory: string;

  @ApiProperty({ description: 'Subcategory' })
  subcategory: string;

  @ApiProperty({ description: 'Suggested tags' })
  tags: string[];

  @ApiProperty({ description: 'Related framework requirements' })
  relatedFrameworks: string[];

  @ApiProperty({ description: 'Confidence level (0-100)' })
  confidence: number;

  @ApiProperty({ description: 'Explanation for categorization' })
  explanation: string;
}

// ============================================
// Smart Search DTOs
// ============================================

export class SmartSearchRequestDto {
  @ApiProperty({ description: 'Natural language search query' })
  @IsString()
  query: string;

  @ApiPropertyOptional({ description: 'Entity types to search', type: [String], enum: EntityType })
  @IsOptional()
  @IsArray()
  @IsEnum(EntityType, { each: true })
  entityTypes?: EntityType[];

  @ApiPropertyOptional({ description: 'Maximum results to return' })
  @IsOptional()
  @IsNumber()
  @Min(1)
  @Max(100)
  limit?: number;
}

export class SearchResultDto {
  @ApiProperty({ description: 'Entity type' })
  entityType: EntityType;

  @ApiProperty({ description: 'Entity ID' })
  id: string;

  @ApiProperty({ description: 'Entity title' })
  title: string;

  @ApiProperty({ description: 'Relevance score (0-100)' })
  relevance: number;

  @ApiProperty({ description: 'Matched snippet' })
  snippet: string;

  @ApiProperty({ description: 'Why this result is relevant' })
  explanation: string;
}

export class SmartSearchResponseDto {
  @ApiProperty({ description: 'Search results', type: [SearchResultDto] })
  results: SearchResultDto[];

  @ApiProperty({ description: 'Query interpretation' })
  interpretation: string;

  @ApiProperty({ description: 'Suggested refinements' })
  suggestedRefinements: string[];

  @ApiProperty({ description: 'Total matching items' })
  totalMatches: number;
}

// ============================================
// Policy Drafting DTOs
// ============================================

export class PolicyDraftRequestDto {
  @ApiProperty({ description: 'Policy type (e.g., Information Security Policy, Acceptable Use Policy)' })
  @IsString()
  policyType: string;

  @ApiProperty({ description: 'Organization name' })
  @IsString()
  organizationName: string;

  @ApiPropertyOptional({ description: 'Industry sector' })
  @IsOptional()
  @IsString()
  industry?: string;

  @ApiPropertyOptional({ description: 'Frameworks to address (SOC 2, ISO 27001, etc.)' })
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  frameworks?: string[];

  @ApiPropertyOptional({ description: 'Specific requirements to include' })
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  requirements?: string[];

  @ApiPropertyOptional({ description: 'Additional context or instructions' })
  @IsOptional()
  @IsString()
  additionalContext?: string;

  @ApiPropertyOptional({ description: 'Desired tone (formal, conversational, technical)' })
  @IsOptional()
  @IsString()
  tone?: string;
}

export class PolicyDraftResponseDto {
  @ApiProperty({ description: 'Generated policy title' })
  title: string;

  @ApiProperty({ description: 'Policy content in markdown' })
  content: string;

  @ApiProperty({ description: 'Suggested sections' })
  sections: PolicySectionDto[];

  @ApiProperty({ description: 'Framework requirements addressed' })
  frameworksCovered: string[];

  @ApiProperty({ description: 'Suggested review schedule' })
  suggestedReviewSchedule: string;

  @ApiProperty({ description: 'Related policies to consider' })
  relatedPolicies: string[];
}

export class PolicySectionDto {
  @ApiProperty({ description: 'Section title' })
  title: string;

  @ApiProperty({ description: 'Section content' })
  content: string;

  @ApiProperty({ description: 'Order in document' })
  order: number;
}

// ============================================
// Control Suggestion DTOs
// ============================================

export class ControlSuggestionRequestDto {
  @ApiPropertyOptional({ description: 'Risk to suggest controls for' })
  @IsOptional()
  @IsString()
  riskDescription?: string;

  @ApiPropertyOptional({ description: 'Framework requirement to address' })
  @IsOptional()
  @IsString()
  frameworkRequirement?: string;

  @ApiPropertyOptional({ description: 'Framework name' })
  @IsOptional()
  @IsString()
  framework?: string;

  @ApiPropertyOptional({ description: 'Existing controls already in place' })
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  existingControls?: string[];

  @ApiPropertyOptional({ description: 'Organization context' })
  @IsOptional()
  @IsString()
  organizationContext?: string;
}

export class SuggestedControlDto {
  @ApiProperty({ description: 'Control title' })
  title: string;

  @ApiProperty({ description: 'Control description' })
  description: string;

  @ApiProperty({ description: 'Control category' })
  category: string;

  @ApiProperty({ description: 'Implementation guidance' })
  implementationGuidance: string;

  @ApiProperty({ description: 'Effort estimate (Low, Medium, High)' })
  effortEstimate: string;

  @ApiProperty({ description: 'Effectiveness rating (1-5)' })
  effectivenessRating: number;

  @ApiProperty({ description: 'Framework mappings' })
  frameworkMappings: string[];

  @ApiProperty({ description: 'Priority (1-5, 1 being highest)' })
  priority: number;
}

export class ControlSuggestionResponseDto {
  @ApiProperty({ description: 'Suggested controls', type: [SuggestedControlDto] })
  controls: SuggestedControlDto[];

  @ApiProperty({ description: 'Gap analysis summary' })
  gapAnalysis: string;

  @ApiProperty({ description: 'Implementation roadmap' })
  implementationRoadmap: string;

  @ApiProperty({ description: 'Estimated total effort' })
  totalEffortEstimate: string;
}

// ============================================
// Generic AI Completion DTOs
// ============================================

export class AICompletionRequestDto {
  @ApiProperty({ description: 'Prompt for AI completion' })
  @IsString()
  prompt: string;

  @ApiPropertyOptional({ description: 'System context/instructions' })
  @IsOptional()
  @IsString()
  systemPrompt?: string;

  @ApiPropertyOptional({ description: 'Temperature override' })
  @IsOptional()
  @IsNumber()
  @Min(0)
  @Max(2)
  temperature?: number;

  @ApiPropertyOptional({ description: 'Max tokens override' })
  @IsOptional()
  @IsNumber()
  maxTokens?: number;
}

export class AICompletionResponseDto {
  @ApiProperty({ description: 'AI response content' })
  content: string;

  @ApiProperty({ description: 'Model used' })
  model: string;

  @ApiProperty({ description: 'Tokens used' })
  tokensUsed: number;

  @ApiProperty({ description: 'Processing time in ms' })
  processingTimeMs: number;
}

// ============================================
// Error Response
// ============================================

export class AIErrorResponseDto {
  @ApiProperty({ description: 'Error code' })
  code: string;

  @ApiProperty({ description: 'Error message' })
  message: string;

  @ApiProperty({ description: 'Whether this is a configuration error' })
  isConfigError: boolean;

  @ApiPropertyOptional({ description: 'Suggested action' })
  suggestedAction?: string;
}
