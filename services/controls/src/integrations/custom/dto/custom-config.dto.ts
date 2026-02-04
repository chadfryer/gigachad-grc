import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsString,
  IsOptional,
  IsIn,
  IsArray,
  ValidateNested,
  IsObject,
  IsUrl,
  MaxLength,
} from 'class-validator';
import { Type } from 'class-transformer';

// Endpoint configuration for visual mode
export class EndpointConfigDto {
  @ApiProperty({ enum: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'] })
  @IsString()
  @IsIn(['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
  method: string;

  @ApiProperty({ description: 'Endpoint path (e.g., /api/users)' })
  @IsString()
  @MaxLength(1000)
  path: string;

  @ApiPropertyOptional({ description: 'Custom headers for this endpoint' })
  @IsOptional()
  @IsObject()
  headers?: Record<string, string>;

  @ApiPropertyOptional({ description: 'Query parameters' })
  @IsOptional()
  @IsObject()
  params?: Record<string, string>;

  @ApiPropertyOptional({ description: 'Request body (for POST/PUT/PATCH)' })
  @IsOptional()
  @IsObject()
  body?: Record<string, unknown>;

  @ApiPropertyOptional({ description: 'JSONPath expressions to extract data from response' })
  @IsOptional()
  @IsObject()
  responseMapping?: {
    title?: string; // JSONPath to extract evidence title
    description?: string; // JSONPath to extract description
    data?: string; // JSONPath to extract main data
  };

  @ApiPropertyOptional({ description: 'Human-readable name for this endpoint' })
  @IsOptional()
  @IsString()
  @MaxLength(255)
  name?: string;

  @ApiPropertyOptional({ description: 'Description of what this endpoint does' })
  @IsOptional()
  @IsString()
  @MaxLength(5000)
  description?: string;
}

// API Key authentication config
export class ApiKeyAuthConfigDto {
  @ApiProperty({ description: 'Header name or query param name' })
  @IsString()
  @MaxLength(255)
  keyName: string;

  @ApiProperty({ description: 'The API key value' })
  @IsString()
  @MaxLength(5000)
  keyValue: string;

  @ApiProperty({ enum: ['header', 'query'], description: 'Where to send the key' })
  @IsString()
  @IsIn(['header', 'query'])
  location: 'header' | 'query';
}

// OAuth 2.0 authentication config
export class OAuth2AuthConfigDto {
  // SECURITY: URL validation prevents SSRF attacks on OAuth token endpoint
  @ApiProperty({ description: 'Token endpoint URL' })
  @IsUrl({}, { message: 'tokenUrl must be a valid URL' })
  @MaxLength(2000)
  tokenUrl: string;

  @ApiProperty({ description: 'Client ID' })
  @IsString()
  @MaxLength(255)
  clientId: string;

  @ApiProperty({ description: 'Client Secret' })
  @IsString()
  @MaxLength(5000)
  clientSecret: string;

  @ApiPropertyOptional({ description: 'OAuth scope' })
  @IsOptional()
  @IsString()
  @MaxLength(1000)
  scope?: string;
}

// Main config DTO for saving custom integration config
export class SaveCustomConfigDto {
  @ApiProperty({ enum: ['visual', 'code'], description: 'Configuration mode' })
  @IsString()
  @IsIn(['visual', 'code'])
  mode: 'visual' | 'code';

  // Visual mode fields
  // SECURITY: URL validation prevents SSRF attacks by ensuring valid URL format
  @ApiPropertyOptional({ description: 'Base URL for API calls' })
  @IsOptional()
  @IsUrl({ require_tld: false }, { message: 'baseUrl must be a valid URL' })
  @MaxLength(2000)
  baseUrl?: string;

  @ApiPropertyOptional({
    type: [EndpointConfigDto],
    description: 'List of endpoint configurations',
  })
  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => EndpointConfigDto)
  endpoints?: EndpointConfigDto[];

  @ApiPropertyOptional({
    enum: ['api_key', 'oauth2', 'basic', 'bearer'],
    description: 'Authentication type',
  })
  @IsOptional()
  @IsString()
  @IsIn(['api_key', 'oauth2', 'basic', 'bearer'])
  authType?: string;

  @ApiPropertyOptional({ description: 'Authentication configuration' })
  @IsOptional()
  @IsObject()
  authConfig?: ApiKeyAuthConfigDto | OAuth2AuthConfigDto | Record<string, unknown>;

  @ApiPropertyOptional({ description: 'Global response mapping configuration' })
  @IsOptional()
  @IsObject()
  responseMapping?: Record<string, unknown>;

  // Code mode fields
  /**
   * SECURITY WARNING: Custom code execution is a significant security risk.
   * This field MUST be:
   * 1. Only accessible to admin users with explicit permissions
   * 2. Executed in a sandboxed environment (VM2, isolated-vm, or similar)
   * 3. Subject to rate limiting and resource constraints
   * 4. Logged for audit purposes with full code content
   * 5. Validated for dangerous patterns before execution
   */
  @ApiPropertyOptional({ description: 'Custom JavaScript code for advanced integrations' })
  @IsOptional()
  @IsString()
  @MaxLength(50000)
  customCode?: string;
}

// DTO for testing an endpoint
export class TestEndpointDto {
  @ApiPropertyOptional({ description: 'Index of endpoint to test (visual mode)' })
  @IsOptional()
  endpointIndex?: number;

  // SECURITY: URL validation prevents SSRF attacks by ensuring valid URL format
  @ApiPropertyOptional({ description: 'Override base URL for testing' })
  @IsOptional()
  @IsUrl({ require_tld: false }, { message: 'baseUrl must be a valid URL' })
  @MaxLength(2000)
  baseUrl?: string;

  @ApiPropertyOptional({ description: 'Override auth config for testing' })
  @IsOptional()
  @IsObject()
  authConfig?: Record<string, unknown>;
}

// Response DTOs
export class CustomConfigResponseDto {
  @ApiProperty()
  id: string;

  @ApiProperty()
  integrationId: string;

  @ApiProperty()
  mode: string;

  @ApiPropertyOptional()
  baseUrl?: string;

  @ApiPropertyOptional()
  endpoints?: EndpointConfigDto[];

  @ApiPropertyOptional()
  authType?: string;

  @ApiPropertyOptional()
  authConfig?: Record<string, unknown>; // Masked for security

  @ApiPropertyOptional()
  responseMapping?: Record<string, unknown>;

  @ApiPropertyOptional()
  customCode?: string;

  @ApiPropertyOptional()
  lastTestAt?: Date;

  @ApiPropertyOptional()
  lastTestStatus?: string;

  @ApiPropertyOptional()
  lastTestError?: string;

  @ApiProperty()
  createdAt: Date;

  @ApiProperty()
  updatedAt: Date;
}

export class TestResultDto {
  @ApiProperty()
  success: boolean;

  @ApiProperty()
  message: string;

  @ApiPropertyOptional()
  statusCode?: number;

  @ApiPropertyOptional()
  responseTime?: number;

  @ApiPropertyOptional()
  data?: unknown;

  @ApiPropertyOptional()
  error?: string;
}

export class ValidateCodeResultDto {
  @ApiProperty()
  valid: boolean;

  @ApiPropertyOptional()
  errors?: string[];

  @ApiPropertyOptional()
  warnings?: string[];
}

// Code template types
export const CODE_TEMPLATE = `/**
 * Custom Integration Code
 * 
 * Available APIs:
 * - fetch(url, options): Make HTTP requests (same as browser fetch)
 * - console.log(...args): Log messages
 * - auth: Pre-configured authentication headers (if auth is set up)
 * 
 * Return format:
 * {
 *   evidence: [
 *     {
 *       title: string,
 *       description: string,
 *       data: any,
 *       type?: string, // 'screenshot', 'document', 'log', 'config', 'report'
 *     }
 *   ]
 * }
 */

async function sync(context) {
  const { baseUrl, auth } = context;
  
  // Example: Fetch data from an API
  const response = await fetch(\`\${baseUrl}/api/data\`, {
    headers: {
      ...auth.headers,
      'Content-Type': 'application/json',
    },
  });
  
  const data = await response.json();
  
  // Return evidence to be created
  return {
    evidence: [
      {
        title: \`API Data - \${new Date().toLocaleDateString()}\`,
        description: 'Data collected from custom API',
        data: data,
        type: 'automated',
      },
    ],
  };
}

// Export the sync function
module.exports = { sync };
`;
