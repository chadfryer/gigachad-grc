/**
 * Common type definitions to reduce `any` usage across the codebase.
 * Import these types instead of using `any` for better type safety.
 */

/**
 * Generic paginated response type.
 */
export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
}

/**
 * Generic API error response.
 */
export interface ApiErrorResponse {
  message: string;
  code?: string;
  statusCode?: number;
  details?: Record<string, unknown>;
}

/**
 * Generic success response.
 */
export interface SuccessResponse {
  success: boolean;
  message?: string;
}

/**
 * Generic ID record from database queries.
 */
export interface IdRecord {
  id: string;
}

/**
 * Generic count record from aggregate queries.
 */
export interface CountRecord {
  count: bigint;
}

/**
 * Generic name record from database queries.
 */
export interface NameRecord {
  name?: string;
  title?: string;
}

/**
 * Job execution result type.
 */
export interface JobResult {
  status: 'success' | 'failed' | 'skipped' | 'pending';
  message?: string;
  isMockMode?: boolean;
  mockModeReason?: string;
  metadata?: Record<string, unknown>;
}

/**
 * Job payload type for job queue.
 */
export interface JobPayload {
  jobType: string;
  organizationId?: string;
  userId?: string;
  entityType?: string;
  entityId?: string;
  data?: Record<string, unknown>;
}

/**
 * Scheduled job configuration.
 */
export interface ScheduledJobConfig {
  id: string;
  name: string;
  cronExpression: string;
  jobType: string;
  enabled: boolean;
  lastRunAt?: Date;
  nextRunAt?: Date;
  payload?: JobPayload;
}

/**
 * Integration connector configuration.
 */
export interface ConnectorConfig {
  baseUrl?: string;
  apiKey?: string;
  apiToken?: string;
  username?: string;
  password?: string;
  organization?: string;
  timeout?: number;
  [key: string]: string | number | boolean | undefined;
}

/**
 * Integration sync result for a collection of items.
 */
export interface SyncCollectionResult<T = unknown> {
  total: number;
  items: T[];
}

/**
 * Integration sync result.
 */
export interface IntegrationSyncResult {
  collectedAt: string;
  errors: string[];
  [key: string]: SyncCollectionResult | string | string[];
}

/**
 * Connection test result.
 */
export interface ConnectionTestResult {
  success: boolean;
  message: string;
  details?: Record<string, unknown>;
}

/**
 * Webhook event payload.
 */
export interface WebhookEventPayload {
  event: string;
  timestamp: string;
  organizationId: string;
  data: Record<string, unknown>;
}

/**
 * Notification payload.
 */
export interface NotificationPayload {
  organizationId: string;
  userId?: string;
  type: string;
  title: string;
  message: string;
  severity?: 'info' | 'warning' | 'error' | 'critical';
  entityType?: string;
  entityId?: string;
  metadata?: Record<string, unknown>;
}

/**
 * Audit log entry.
 */
export interface AuditLogEntry {
  organizationId: string;
  userId: string;
  userEmail?: string;
  userName?: string;
  action: string;
  entityType: string;
  entityId: string;
  entityName?: string;
  description?: string;
  changes?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
  timestamp?: Date;
}

/**
 * User context from authentication.
 */
export interface UserContext {
  userId: string;
  keycloakId?: string;
  email: string;
  organizationId: string;
  role: string;
  permissions: string[];
  name?: string;
}

/**
 * Filter options for list queries.
 */
export interface BaseFilterOptions {
  search?: string;
  page?: number;
  limit?: number;
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
}

/**
 * Date range filter.
 */
export interface DateRangeFilter {
  startDate?: Date | string;
  endDate?: Date | string;
}

/**
 * Entity with common audit fields.
 */
export interface AuditableEntity {
  id: string;
  createdAt: Date;
  updatedAt: Date;
  createdBy?: string;
  updatedBy?: string;
  deletedAt?: Date;
  deletedBy?: string;
}

/**
 * Entity with organization scope.
 */
export interface OrganizationScopedEntity extends AuditableEntity {
  organizationId: string;
}

/**
 * Prisma client type for dependency injection.
 * Use this instead of `any` when injecting Prisma.
 */
export type PrismaClient = {
  organization: unknown;
  user: unknown;
  [key: string]: unknown;
};
