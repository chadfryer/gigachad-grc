import { IsString, IsOptional, IsEnum, IsArray, IsObject, ValidateNested, IsBoolean, IsNumber, MaxLength } from 'class-validator';
import { Type } from 'class-transformer';

// Transport types for MCP servers
export enum MCPTransportType {
  STDIO = 'stdio',
  SSE = 'sse',
  WEBSOCKET = 'websocket',
}

// Server status
export enum MCPServerStatus {
  CONNECTED = 'connected',
  DISCONNECTED = 'disconnected',
  CONNECTING = 'connecting',
  ERROR = 'error',
}

// Server capability categories
export enum MCPCapabilityCategory {
  EVIDENCE_COLLECTION = 'evidence-collection',
  COMPLIANCE_CHECK = 'compliance-check',
  AI_ANALYSIS = 'ai-analysis',
  DATA_SYNC = 'data-sync',
  NOTIFICATIONS = 'notifications',
  CLOUD_SCANNING = 'cloud-scanning',
  VERSION_CONTROL = 'version-control',
  DATABASE = 'database',
  FILESYSTEM = 'filesystem',
}

// MCP Tool Definition
export class MCPToolDefinition {
  @IsString()
  name: string;

  @IsString()
  @IsOptional()
  description?: string;

  @IsObject()
  @IsOptional()
  inputSchema?: Record<string, unknown>;

  @IsArray()
  @IsString({ each: true })
  @IsOptional()
  requiredParams?: string[];
}

// MCP Resource Definition
export class MCPResourceDefinition {
  @IsString()
  uri: string;

  @IsString()
  name: string;

  @IsString()
  @IsOptional()
  description?: string;

  @IsString()
  @IsOptional()
  mimeType?: string;
}

// MCP Prompt Definition
export class MCPPromptDefinition {
  @IsString()
  name: string;

  @IsString()
  @IsOptional()
  description?: string;

  @IsArray()
  @IsOptional()
  arguments?: Array<{
    name: string;
    description?: string;
    required?: boolean;
  }>;
}

// Server capabilities response
export class MCPCapabilities {
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => MCPToolDefinition)
  tools: MCPToolDefinition[];

  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => MCPResourceDefinition)
  resources: MCPResourceDefinition[];

  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => MCPPromptDefinition)
  prompts: MCPPromptDefinition[];
}

// Server configuration DTO
export class MCPServerConfigDto {
  @IsString()
  id: string;

  @IsString()
  name: string;

  @IsEnum(MCPTransportType)
  transport: MCPTransportType;

  @IsString()
  @IsOptional()
  command?: string; // For stdio transport

  @IsArray()
  @IsString({ each: true })
  @IsOptional()
  args?: string[]; // Command arguments for stdio

  @IsString()
  @IsOptional()
  url?: string; // For SSE/WebSocket transport

  @IsObject()
  @IsOptional()
  env?: Record<string, string>; // Environment variables

  @IsArray()
  @IsString({ each: true })
  @IsOptional()
  capabilities?: string[]; // Expected capability categories

  @IsBoolean()
  @IsOptional()
  autoConnect?: boolean;

  @IsNumber()
  @IsOptional()
  timeout?: number; // Connection timeout in ms

  @IsNumber()
  @IsOptional()
  retryAttempts?: number;
}

// Create server request
export class CreateMCPServerDto {
  @IsString()
  name: string;

  @IsEnum(MCPTransportType)
  transport: MCPTransportType;

  @IsString()
  @IsOptional()
  command?: string;

  @IsArray()
  @IsString({ each: true })
  @IsOptional()
  args?: string[];

  @IsString()
  @IsOptional()
  url?: string;

  @IsObject()
  @IsOptional()
  env?: Record<string, string>;

  @IsArray()
  @IsString({ each: true })
  @IsOptional()
  capabilities?: string[];

  @IsBoolean()
  @IsOptional()
  autoConnect?: boolean;
}

// Update server request
export class UpdateMCPServerDto {
  @IsString()
  @IsOptional()
  name?: string;

  @IsEnum(MCPTransportType)
  @IsOptional()
  transport?: MCPTransportType;

  @IsString()
  @IsOptional()
  command?: string;

  @IsArray()
  @IsString({ each: true })
  @IsOptional()
  args?: string[];

  @IsString()
  @IsOptional()
  url?: string;

  @IsObject()
  @IsOptional()
  env?: Record<string, string>;

  @IsBoolean()
  @IsOptional()
  autoConnect?: boolean;
}

// Tool call request
export class MCPToolCallDto {
  @IsString()
  serverId: string;

  @IsString()
  toolName: string;

  @IsObject()
  @IsOptional()
  arguments?: Record<string, unknown>;
}

// Tool call response
export class MCPToolCallResponseDto {
  @IsBoolean()
  success: boolean;

  @IsObject()
  @IsOptional()
  result?: unknown;

  @IsString()
  @IsOptional()
  error?: string;

  @IsNumber()
  @IsOptional()
  executionTimeMs?: number;
}

// Resource request
export class MCPResourceRequestDto {
  @IsString()
  serverId: string;

  @IsString()
  uri: string;
}

// Resource response
export class MCPResourceResponseDto {
  @IsString()
  uri: string;

  @IsString()
  @IsOptional()
  mimeType?: string;

  @IsOptional()
  content: unknown;
}

// Prompt request
export class MCPPromptRequestDto {
  @IsString()
  serverId: string;

  @IsString()
  promptName: string;

  @IsObject()
  @IsOptional()
  arguments?: Record<string, string>;
}

// Prompt response
export class MCPPromptResponseDto {
  @IsString()
  @IsOptional()
  description?: string;

  @IsArray()
  messages: Array<{
    role: 'user' | 'assistant' | 'system';
    content: string;
  }>;
}

// Server status response
// Configuration details for audit purposes
export class MCPServerConfigurationDto {
  @IsArray()
  @IsString({ each: true })
  configuredIntegrations: string[];

  @IsArray()
  @IsString({ each: true })
  evidenceTypes: string[];

  @IsString()
  command: string;

  @IsArray()
  @IsString({ each: true })
  args: string[];
}

export class MCPServerStatusDto {
  @IsString()
  id: string;

  @IsString()
  name: string;

  @IsEnum(MCPServerStatus)
  status: MCPServerStatus;

  @IsEnum(MCPTransportType)
  transport: MCPTransportType;

  @IsString()
  @IsOptional()
  templateId?: string;

  @IsString()
  @IsOptional()
  lastConnected?: string;

  @IsString()
  @IsOptional()
  lastError?: string;

  @IsString()
  @IsOptional()
  createdAt?: string;

  @IsString()
  @IsOptional()
  createdBy?: string;

  @ValidateNested()
  @Type(() => MCPServerConfigurationDto)
  @IsOptional()
  configuration?: MCPServerConfigurationDto;

  @ValidateNested()
  @Type(() => MCPCapabilities)
  @IsOptional()
  capabilities?: MCPCapabilities;
}

// Batch tool call request
export class MCPBatchToolCallDto {
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => MCPToolCallDto)
  calls: MCPToolCallDto[];

  @IsBoolean()
  @IsOptional()
  parallel?: boolean; // Execute in parallel or sequential
}

// Batch tool call response
export class MCPBatchToolCallResponseDto {
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => MCPToolCallResponseDto)
  results: MCPToolCallResponseDto[];

  @IsNumber()
  totalExecutionTimeMs: number;

  @IsNumber()
  successCount: number;

  @IsNumber()
  errorCount: number;
}

// Server health check
export class MCPHealthCheckDto {
  @IsString()
  serverId: string;

  @IsBoolean()
  isHealthy: boolean;

  @IsNumber()
  @IsOptional()
  latencyMs?: number;

  @IsString()
  @IsOptional()
  version?: string;

  @IsString()
  checkedAt: string;
}

// MCP Event types for real-time updates
export enum MCPEventType {
  SERVER_CONNECTED = 'server_connected',
  SERVER_DISCONNECTED = 'server_disconnected',
  SERVER_ERROR = 'server_error',
  TOOL_EXECUTED = 'tool_executed',
  RESOURCE_UPDATED = 'resource_updated',
}

// MCP Event DTO
export class MCPEventDto {
  @IsEnum(MCPEventType)
  type: MCPEventType;

  @IsString()
  serverId: string;

  @IsString()
  timestamp: string;

  @IsObject()
  @IsOptional()
  data?: Record<string, unknown>;
}

// DTOs for MCP Controller endpoints
export class CallToolDto {
  @IsString()
  @MaxLength(255)
  toolName: string;

  @IsObject()
  params: Record<string, unknown>;
}

export class GetPromptDto {
  @IsString()
  @MaxLength(255)
  name: string;

  @IsObject()
  @IsOptional()
  args?: Record<string, unknown>;
}

export class ReadResourceDto {
  @IsString()
  @MaxLength(2000)
  uri: string;
}

