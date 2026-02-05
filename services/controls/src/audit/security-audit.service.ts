import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { Prisma } from '@prisma/client';

/**
 * Security event types for comprehensive audit logging
 */
export enum SecurityEventType {
  // Authentication events
  AUTH_LOGIN_SUCCESS = 'auth.login.success',
  AUTH_LOGIN_FAILED = 'auth.login.failed',
  AUTH_LOGOUT = 'auth.logout',
  AUTH_SESSION_CREATED = 'auth.session.created',
  AUTH_SESSION_EXPIRED = 'auth.session.expired',
  AUTH_SESSION_REVOKED = 'auth.session.revoked',
  AUTH_PASSWORD_CHANGED = 'auth.password.changed',
  AUTH_PASSWORD_RESET_REQUESTED = 'auth.password_reset.requested',
  AUTH_PASSWORD_RESET_COMPLETED = 'auth.password_reset.completed',
  AUTH_MFA_ENABLED = 'auth.mfa.enabled',
  AUTH_MFA_DISABLED = 'auth.mfa.disabled',

  // API Key events
  API_KEY_CREATED = 'api_key.created',
  API_KEY_USED = 'api_key.used',
  API_KEY_REVOKED = 'api_key.revoked',
  API_KEY_EXPIRED = 'api_key.expired',

  // Permission events
  PERMISSION_GRANTED = 'permission.granted',
  PERMISSION_REVOKED = 'permission.revoked',
  PERMISSION_CHECK_FAILED = 'permission.check_failed',
  ROLE_ASSIGNED = 'role.assigned',
  ROLE_REMOVED = 'role.removed',

  // Data access events
  DATA_EXPORT = 'data.export',
  DATA_BULK_DELETE = 'data.bulk_delete',
  DATA_BULK_UPDATE = 'data.bulk_update',
  DATA_IMPORT = 'data.import',
  SENSITIVE_DATA_ACCESS = 'data.sensitive_access',

  // Admin events
  ADMIN_USER_CREATED = 'admin.user.created',
  ADMIN_USER_DELETED = 'admin.user.deleted',
  ADMIN_USER_MODIFIED = 'admin.user.modified',
  ADMIN_SETTINGS_CHANGED = 'admin.settings.changed',
  ADMIN_MODULE_ENABLED = 'admin.module.enabled',
  ADMIN_MODULE_DISABLED = 'admin.module.disabled',
  ADMIN_INTEGRATION_CONFIGURED = 'admin.integration.configured',

  // Security alerts
  SECURITY_BRUTE_FORCE_DETECTED = 'security.brute_force.detected',
  SECURITY_SUSPICIOUS_ACTIVITY = 'security.suspicious_activity',
  SECURITY_UNAUTHORIZED_ACCESS = 'security.unauthorized_access',
  SECURITY_RATE_LIMIT_EXCEEDED = 'security.rate_limit.exceeded',
  SECURITY_INVALID_TOKEN = 'security.invalid_token',

  // Compliance events
  COMPLIANCE_EVIDENCE_UPLOADED = 'compliance.evidence.uploaded',
  COMPLIANCE_CONTROL_STATUS_CHANGED = 'compliance.control.status_changed',
  COMPLIANCE_AUDIT_STARTED = 'compliance.audit.started',
  COMPLIANCE_AUDIT_COMPLETED = 'compliance.audit.completed',
}

/**
 * Severity levels for security events
 */
export enum SecurityEventSeverity {
  INFO = 'info',
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical',
}

/**
 * Parameters for logging a security event
 */
export interface SecurityEventParams {
  eventType: SecurityEventType | string;
  severity?: SecurityEventSeverity;
  userId?: string | null;
  userEmail?: string;
  organizationId: string;
  ipAddress?: string;
  userAgent?: string;
  resourceType?: string;
  resourceId?: string;
  description: string;
  details?: Record<string, unknown>;
  success?: boolean;
}

/**
 * Configuration for security alerts
 */
export interface SecurityAlertConfig {
  enabled: boolean;
  slackWebhookUrl?: string;
  emailRecipients?: string[];
  alertThreshold: SecurityEventSeverity;
}

/**
 * Service for comprehensive security audit logging and alerting
 *
 * This service provides structured logging for all security-relevant events
 * including authentication, authorization, data access, and admin actions.
 *
 * SECURITY: High and Critical severity events trigger real-time alerts.
 */
@Injectable()
export class SecurityAuditService {
  private readonly logger = new Logger(SecurityAuditService.name);
  private readonly alertConfig: SecurityAlertConfig;

  /**
   * Track failed login attempts for brute force detection
   * Key: IP address or email, Value: { count, firstAttempt, lastAttempt }
   */
  private failedLoginAttempts = new Map<
    string,
    {
      count: number;
      firstAttempt: Date;
      lastAttempt: Date;
    }
  >();

  /**
   * Brute force detection thresholds
   */
  private readonly BRUTE_FORCE_THRESHOLD = 5;
  private readonly BRUTE_FORCE_WINDOW_MS = 5 * 60 * 1000; // 5 minutes

  constructor(private readonly prisma: PrismaService) {
    this.alertConfig = {
      enabled: process.env.SECURITY_ALERTS_ENABLED === 'true',
      slackWebhookUrl: process.env.SECURITY_ALERTS_SLACK_WEBHOOK,
      emailRecipients: process.env.SECURITY_ALERTS_EMAIL_RECIPIENTS?.split(',').filter(Boolean),
      alertThreshold:
        (process.env.SECURITY_ALERTS_THRESHOLD as SecurityEventSeverity) ||
        SecurityEventSeverity.HIGH,
    };

    if (this.alertConfig.enabled) {
      this.logger.log('Security alerting enabled');
    }

    // Cleanup old entries periodically
    setInterval(() => this.cleanupFailedAttempts(), 60 * 1000);
  }

  /**
   * SECURITY: Send real-time alert for security events
   * Triggered for events at or above the configured threshold
   */
  private async sendSecurityAlert(params: SecurityEventParams): Promise<void> {
    if (!this.alertConfig.enabled) return;

    const severity = params.severity || SecurityEventSeverity.INFO;
    const severityOrder = [
      SecurityEventSeverity.INFO,
      SecurityEventSeverity.LOW,
      SecurityEventSeverity.MEDIUM,
      SecurityEventSeverity.HIGH,
      SecurityEventSeverity.CRITICAL,
    ];

    const eventLevel = severityOrder.indexOf(severity);
    const thresholdLevel = severityOrder.indexOf(this.alertConfig.alertThreshold);

    if (eventLevel < thresholdLevel) return;

    const alertMessage = this.formatAlertMessage(params);

    // Send to Slack
    if (this.alertConfig.slackWebhookUrl) {
      await this.sendSlackAlert(alertMessage, severity);
    }

    // Log for monitoring systems (can be picked up by log aggregators)
    this.logger.warn(
      `[SECURITY ALERT] ${severity.toUpperCase()} - ${params.eventType}: ${params.description}`
    );
  }

  /**
   * Format alert message for notifications
   */
  private formatAlertMessage(params: SecurityEventParams): string {
    const timestamp = new Date().toISOString();
    const details = params.details ? JSON.stringify(params.details, null, 2) : 'N/A';

    return `
🚨 Security Alert - ${params.severity?.toUpperCase() || 'INFO'}

Event: ${params.eventType}
Time: ${timestamp}
Organization: ${params.organizationId}
User: ${params.userEmail || params.userId || 'Anonymous'}
IP: ${params.ipAddress || 'Unknown'}

Description: ${params.description}

Details: ${details}
    `.trim();
  }

  /**
   * Send alert to Slack webhook
   */
  private async sendSlackAlert(message: string, severity: SecurityEventSeverity): Promise<void> {
    if (!this.alertConfig.slackWebhookUrl) return;

    try {
      const color =
        severity === SecurityEventSeverity.CRITICAL
          ? '#dc3545'
          : severity === SecurityEventSeverity.HIGH
            ? '#fd7e14'
            : severity === SecurityEventSeverity.MEDIUM
              ? '#ffc107'
              : '#17a2b8';

      const response = await fetch(this.alertConfig.slackWebhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          attachments: [
            {
              color,
              title: `Security Alert - ${severity.toUpperCase()}`,
              text: message,
              ts: Math.floor(Date.now() / 1000),
            },
          ],
        }),
      });

      if (!response.ok) {
        this.logger.error(`Failed to send Slack alert: ${response.status}`);
      }
    } catch (error) {
      this.logger.error(`Error sending Slack alert: ${error}`);
    }
  }

  /**
   * Track and detect brute force attacks
   */
  private async trackFailedAttempt(
    identifier: string,
    ipAddress: string,
    _organizationId: string
  ): Promise<void> {
    const now = new Date();
    const key = `${ipAddress}:${identifier}`;

    const existing = this.failedLoginAttempts.get(key);

    if (existing) {
      // Check if within window
      if (now.getTime() - existing.firstAttempt.getTime() > this.BRUTE_FORCE_WINDOW_MS) {
        // Reset if outside window
        this.failedLoginAttempts.set(key, { count: 1, firstAttempt: now, lastAttempt: now });
      } else {
        // Increment count
        existing.count++;
        existing.lastAttempt = now;

        // Check threshold
        if (existing.count >= this.BRUTE_FORCE_THRESHOLD) {
          await this.logBruteForceDetected({
            identifier,
            ipAddress,
            attemptCount: existing.count,
          });

          // Reset after alerting
          this.failedLoginAttempts.delete(key);
        }
      }
    } else {
      this.failedLoginAttempts.set(key, { count: 1, firstAttempt: now, lastAttempt: now });
    }
  }

  /**
   * Cleanup expired failed attempt tracking entries
   */
  private cleanupFailedAttempts(): void {
    const now = Date.now();
    for (const [key, value] of this.failedLoginAttempts.entries()) {
      if (now - value.lastAttempt.getTime() > this.BRUTE_FORCE_WINDOW_MS) {
        this.failedLoginAttempts.delete(key);
      }
    }
  }

  /**
   * Log a security event
   *
   * SECURITY: High and Critical severity events trigger real-time alerts
   */
  async logSecurityEvent(params: SecurityEventParams): Promise<void> {
    const {
      eventType,
      severity = SecurityEventSeverity.INFO,
      userId,
      userEmail,
      organizationId,
      ipAddress,
      userAgent,
      resourceType,
      resourceId,
      description,
      details = {},
      success = true,
    } = params;

    try {
      await this.prisma.auditLog.create({
        data: {
          organizationId,
          userId,
          userEmail,
          action: eventType,
          entityType: resourceType || 'security',
          entityId: resourceId || 'system',
          description,
          metadata: {
            ...details,
            severity,
            success,
            userAgent,
            eventTimestamp: new Date().toISOString(),
          },
          ipAddress,
        },
      });

      // Log to console for high severity events
      if (severity === SecurityEventSeverity.HIGH || severity === SecurityEventSeverity.CRITICAL) {
        this.logger.warn(
          `[SECURITY ${severity.toUpperCase()}] ${eventType}: ${description} ` +
            `(user=${userId || 'anonymous'}, ip=${ipAddress || 'unknown'})`
        );
      }

      // Send real-time alert for high/critical severity events
      await this.sendSecurityAlert(params);
    } catch (error) {
      this.logger.error(`Failed to log security event: ${error}`);
      // Don't throw - logging failures shouldn't break the application
    }
  }

  // ===========================
  // Authentication Events
  // ===========================

  async logLoginSuccess(params: {
    userId: string;
    userEmail: string;
    organizationId: string;
    ipAddress: string;
    userAgent?: string;
    method?: string;
  }): Promise<void> {
    await this.logSecurityEvent({
      eventType: SecurityEventType.AUTH_LOGIN_SUCCESS,
      severity: SecurityEventSeverity.INFO,
      ...params,
      description: `Successful login from ${params.ipAddress}`,
      details: { method: params.method || 'password' },
    });
  }

  async logLoginFailed(params: {
    userEmail: string;
    organizationId: string;
    ipAddress: string;
    userAgent?: string;
    reason: string;
    attemptCount?: number;
  }): Promise<void> {
    const severity =
      (params.attemptCount || 0) >= 5 ? SecurityEventSeverity.HIGH : SecurityEventSeverity.MEDIUM;

    await this.logSecurityEvent({
      eventType: SecurityEventType.AUTH_LOGIN_FAILED,
      severity,
      ...params,
      userId: null,
      description: `Failed login attempt: ${params.reason}`,
      details: {
        attemptCount: params.attemptCount,
        reason: params.reason,
      },
      success: false,
    });

    // Track for brute force detection
    await this.trackFailedAttempt(params.userEmail, params.ipAddress, params.organizationId);
  }

  async logLogout(params: {
    userId: string;
    organizationId: string;
    ipAddress?: string;
    allDevices?: boolean;
  }): Promise<void> {
    await this.logSecurityEvent({
      eventType: SecurityEventType.AUTH_LOGOUT,
      severity: SecurityEventSeverity.INFO,
      ...params,
      description: params.allDevices ? 'User logged out from all devices' : 'User logged out',
      details: { allDevices: params.allDevices },
    });
  }

  async logPasswordChange(params: {
    userId: string;
    organizationId: string;
    ipAddress?: string;
    initiatedBy?: string;
  }): Promise<void> {
    await this.logSecurityEvent({
      eventType: SecurityEventType.AUTH_PASSWORD_CHANGED,
      severity: SecurityEventSeverity.MEDIUM,
      ...params,
      description: 'Password changed',
      details: { initiatedBy: params.initiatedBy || 'user' },
    });
  }

  // ===========================
  // API Key Events
  // ===========================

  async logApiKeyCreated(params: {
    userId: string;
    organizationId: string;
    apiKeyId: string;
    apiKeyName: string;
    scopes: string[];
  }): Promise<void> {
    await this.logSecurityEvent({
      eventType: SecurityEventType.API_KEY_CREATED,
      severity: SecurityEventSeverity.MEDIUM,
      ...params,
      resourceType: 'api_key',
      resourceId: params.apiKeyId,
      description: `API key created: ${params.apiKeyName}`,
      details: { scopes: params.scopes },
    });
  }

  async logApiKeyUsed(params: {
    organizationId: string;
    apiKeyId: string;
    apiKeyName: string;
    ipAddress: string;
    endpoint: string;
  }): Promise<void> {
    await this.logSecurityEvent({
      eventType: SecurityEventType.API_KEY_USED,
      severity: SecurityEventSeverity.INFO,
      ...params,
      resourceType: 'api_key',
      resourceId: params.apiKeyId,
      description: `API key used: ${params.apiKeyName}`,
      details: { endpoint: params.endpoint },
    });
  }

  async logApiKeyRevoked(params: {
    userId: string;
    organizationId: string;
    apiKeyId: string;
    apiKeyName: string;
    reason?: string;
  }): Promise<void> {
    await this.logSecurityEvent({
      eventType: SecurityEventType.API_KEY_REVOKED,
      severity: SecurityEventSeverity.MEDIUM,
      ...params,
      resourceType: 'api_key',
      resourceId: params.apiKeyId,
      description: `API key revoked: ${params.apiKeyName}`,
      details: { reason: params.reason },
    });
  }

  // ===========================
  // Permission Events
  // ===========================

  async logPermissionCheckFailed(params: {
    userId: string;
    organizationId: string;
    resource: string;
    action: string;
    resourceId?: string;
    ipAddress?: string;
  }): Promise<void> {
    await this.logSecurityEvent({
      eventType: SecurityEventType.PERMISSION_CHECK_FAILED,
      severity: SecurityEventSeverity.MEDIUM,
      ...params,
      resourceType: params.resource,
      resourceId: params.resourceId,
      description: `Permission denied: ${params.action} on ${params.resource}`,
      success: false,
    });
  }

  async logRoleAssigned(params: {
    userId: string;
    organizationId: string;
    targetUserId: string;
    role: string;
  }): Promise<void> {
    await this.logSecurityEvent({
      eventType: SecurityEventType.ROLE_ASSIGNED,
      severity: SecurityEventSeverity.MEDIUM,
      ...params,
      resourceType: 'user',
      resourceId: params.targetUserId,
      description: `Role '${params.role}' assigned to user`,
      details: { targetUserId: params.targetUserId, role: params.role },
    });
  }

  // ===========================
  // Data Events
  // ===========================

  async logDataExport(params: {
    userId: string;
    organizationId: string;
    exportType: string;
    recordCount: number;
    ipAddress?: string;
  }): Promise<void> {
    await this.logSecurityEvent({
      eventType: SecurityEventType.DATA_EXPORT,
      severity: SecurityEventSeverity.MEDIUM,
      ...params,
      resourceType: 'export',
      description: `Data exported: ${params.exportType} (${params.recordCount} records)`,
      details: { exportType: params.exportType, recordCount: params.recordCount },
    });
  }

  async logBulkOperation(params: {
    userId: string;
    organizationId: string;
    operation: 'delete' | 'update';
    entityType: string;
    recordCount: number;
    ipAddress?: string;
  }): Promise<void> {
    const eventType =
      params.operation === 'delete'
        ? SecurityEventType.DATA_BULK_DELETE
        : SecurityEventType.DATA_BULK_UPDATE;

    await this.logSecurityEvent({
      eventType,
      severity: SecurityEventSeverity.HIGH,
      ...params,
      resourceType: params.entityType,
      description: `Bulk ${params.operation}: ${params.recordCount} ${params.entityType} records`,
      details: { operation: params.operation, recordCount: params.recordCount },
    });
  }

  // ===========================
  // Security Alerts
  // ===========================

  async logBruteForceDetected(params: {
    identifier: string;
    ipAddress: string;
    attemptCount: number;
  }): Promise<void> {
    await this.logSecurityEvent({
      eventType: SecurityEventType.SECURITY_BRUTE_FORCE_DETECTED,
      severity: SecurityEventSeverity.CRITICAL,
      organizationId: '00000000-0000-0000-0000-000000000000', // System
      userId: null,
      userEmail: params.identifier,
      ipAddress: params.ipAddress,
      description: `Brute force attack detected: ${params.attemptCount} failed attempts`,
      details: {
        identifier: params.identifier,
        attemptCount: params.attemptCount,
        alertType: 'brute_force',
      },
      success: false,
    });
  }

  async logRateLimitExceeded(params: {
    userId?: string;
    organizationId: string;
    ipAddress: string;
    endpoint: string;
    limit: number;
  }): Promise<void> {
    await this.logSecurityEvent({
      eventType: SecurityEventType.SECURITY_RATE_LIMIT_EXCEEDED,
      severity: SecurityEventSeverity.MEDIUM,
      ...params,
      description: `Rate limit exceeded on ${params.endpoint}`,
      details: { endpoint: params.endpoint, limit: params.limit },
      success: false,
    });
  }

  async logUnauthorizedAccess(params: {
    userId?: string;
    organizationId: string;
    ipAddress: string;
    resource: string;
    resourceId?: string;
    reason: string;
  }): Promise<void> {
    await this.logSecurityEvent({
      eventType: SecurityEventType.SECURITY_UNAUTHORIZED_ACCESS,
      severity: SecurityEventSeverity.HIGH,
      ...params,
      resourceType: params.resource,
      resourceId: params.resourceId,
      description: `Unauthorized access attempt: ${params.reason}`,
      details: { reason: params.reason },
      success: false,
    });
  }

  // ===========================
  // Admin Events
  // ===========================

  async logAdminAction(params: {
    userId: string;
    organizationId: string;
    action: string;
    targetType: string;
    targetId: string;
    changes?: Record<string, unknown>;
    ipAddress?: string;
  }): Promise<void> {
    await this.logSecurityEvent({
      eventType: `admin.${params.action}`,
      severity: SecurityEventSeverity.MEDIUM,
      ...params,
      resourceType: params.targetType,
      resourceId: params.targetId,
      description: `Admin action: ${params.action} on ${params.targetType}`,
      details: { changes: params.changes },
    });
  }

  async logSettingsChanged(params: {
    userId: string;
    organizationId: string;
    settingName: string;
    oldValue?: unknown;
    newValue?: unknown;
    ipAddress?: string;
  }): Promise<void> {
    await this.logSecurityEvent({
      eventType: SecurityEventType.ADMIN_SETTINGS_CHANGED,
      severity: SecurityEventSeverity.MEDIUM,
      ...params,
      resourceType: 'settings',
      resourceId: params.settingName,
      description: `Setting changed: ${params.settingName}`,
      details: {
        settingName: params.settingName,
        oldValue: params.oldValue,
        newValue: params.newValue,
      },
    });
  }

  // ===========================
  // Query Methods
  // ===========================

  /**
   * Get security events for an organization
   */
  async getSecurityEvents(
    organizationId: string,
    filters: {
      eventTypes?: string[];
      severity?: SecurityEventSeverity[];
      userId?: string;
      startDate?: Date;
      endDate?: Date;
      limit?: number;
      offset?: number;
    } = {}
  ) {
    const where: Prisma.AuditLogWhereInput = { organizationId };

    if (filters.eventTypes?.length) {
      where.action = { in: filters.eventTypes };
    }

    if (filters.userId) {
      where.userId = filters.userId;
    }

    if (filters.startDate || filters.endDate) {
      where.timestamp = {};
      if (filters.startDate) where.timestamp.gte = filters.startDate;
      if (filters.endDate) where.timestamp.lte = filters.endDate;
    }

    // Filter by severity if provided (stored in details.severity)
    // Note: This requires JSONB query support

    const [events, total] = await Promise.all([
      this.prisma.auditLog.findMany({
        where,
        orderBy: { timestamp: 'desc' },
        take: filters.limit || 100,
        skip: filters.offset || 0,
      }),
      this.prisma.auditLog.count({ where }),
    ]);

    return { events, total };
  }
}
