// Base types from common.ts (primary definitions)
export * from './common';

// Additional types from common.types.ts (only non-conflicting)
// Note: PaginatedResponse and IntegrationSyncResult are already in other files
export {
  ApiErrorResponse,
  SuccessResponse,
  IdRecord,
  CountRecord,
  NameRecord,
  JobResult,
  JobPayload,
  ScheduledJobConfig,
  ConnectorConfig,
  SyncCollectionResult,
  ConnectionTestResult,
  WebhookEventPayload,
  NotificationPayload,
  AuditLogEntry,
  UserContext,
  BaseFilterOptions,
  DateRangeFilter,
  AuditableEntity,
  OrganizationScopedEntity,
  PrismaClient,
} from './common.types';

export * from './organization';
export * from './user';
export * from './control';
export * from './evidence';
export * from './framework';
export * from './policy';

// Integration types from integration.ts (primary definitions)
export * from './integration';

// Additional types from integration.types.ts (only non-conflicting)
export {
  AuthType,
  IntegrationCredentials,
  FieldMapping,
  IntegrationFilter,
  IntegrationSyncStats,
  IntegrationSyncError,
  IntegrationWebhookPayload,
  TestIntegrationResult,
  JiraIssue,
  SlackChannel,
  AWSSecurityFinding,
  VulnerabilityScanResult,
} from './integration.types';

export * from './audit-log';
export * from './request.types';
export * from './error.types';
export * from './event.types';
export * from './prisma-helpers.types';

// Dashboard and widget types (only non-conflicting with user.ts)
// DashboardWidget is already exported from user.ts
export {
  WidgetType,
  ChartType,
  WidgetSize,
  WidgetPosition,
  WidgetDataSource,
  WidgetChartConfig,
  WidgetTableConfig,
  WidgetStatsConfig,
  WidgetConfig,
  Dashboard,
  CreateDashboardDto,
  UpdateDashboardDto,
  CreateWidgetDto,
  UpdateWidgetDto,
} from './widget.types';

// Workflow automation types
export * from './workflow.types';
