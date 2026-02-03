/**
 * Error tracking utility for production error monitoring
 * 
 * Supports:
 * - Sentry (when installed and configured)
 * - Console logging (development/fallback)
 * 
 * Note: To enable Sentry, install @sentry/react package and set VITE_SENTRY_DSN
 */

export interface ErrorContext {
  userId?: string;
  organizationId?: string;
  componentStack?: string;
  tags?: Record<string, string>;
  extra?: Record<string, unknown>;
}

interface ErrorTrackingConfig {
  dsn?: string;
  environment: string;
  enabled: boolean;
  release?: string;
}

// Error tracking singleton
class ErrorTrackingService {
  private config: ErrorTrackingConfig;
  private initialized = false;
  private sentryModule: typeof import('@sentry/react') | null = null;

  constructor() {
    this.config = {
      dsn: import.meta.env.VITE_SENTRY_DSN,
      environment: import.meta.env.VITE_ENV || import.meta.env.MODE || 'development',
      enabled: import.meta.env.VITE_ERROR_TRACKING_ENABLED === 'true',
      release: import.meta.env.VITE_APP_VERSION || 'unknown',
    };
  }

  /**
   * Initialize error tracking service
   * Should be called once at app startup
   */
  async init(): Promise<void> {
    if (this.initialized) return;
    this.initialized = true;

    if (!this.config.enabled) {
      // Suppress error tracking disabled log
      // console.info('[ErrorTracking] Disabled - VITE_ERROR_TRACKING_ENABLED is not "true"');
      return;
    }

    if (!this.config.dsn) {
      console.info('[ErrorTracking] No DSN configured - using console logging only');
      return;
    }

    // Try to dynamically import Sentry - this will fail gracefully if not installed
    try {
      // Use a variable to prevent Vite from statically analyzing this import
      const sentryPackage = '@sentry/react';
      this.sentryModule = await import(/* @vite-ignore */ sentryPackage);
      
      this.sentryModule!.init({
        dsn: this.config.dsn,
        environment: this.config.environment,
        release: this.config.release,
        integrations: [
          this.sentryModule!.browserTracingIntegration(),
          this.sentryModule!.replayIntegration({
            maskAllText: true,
            blockAllMedia: true,
          }),
        ],
        // Performance Monitoring
        tracesSampleRate: this.config.environment === 'production' ? 0.2 : 1.0,
        // Session Replay
        replaysSessionSampleRate: 0.1,
        replaysOnErrorSampleRate: 1.0,
        // Filter out common noise
        ignoreErrors: [
          'ResizeObserver loop limit exceeded',
          'ResizeObserver loop completed with undelivered notifications',
          'Non-Error promise rejection captured',
          /Loading chunk [\d]+ failed/,
        ],
        beforeSend(event, hint) {
          // Don't send errors in development
          if (import.meta.env.DEV) {
            console.error('[Sentry would send]:', hint.originalException || hint.syntheticException);
            return null;
          }
          return event;
        },
      });

      console.info('[ErrorTracking] Sentry initialized successfully');
    } catch {
      // Sentry not installed or failed to load - that's okay, we'll use console logging
      console.info('[ErrorTracking] Sentry not available - using console logging only');
      console.debug('[ErrorTracking] To enable Sentry: npm install @sentry/react');
    }
  }

  /**
   * Set user context for error tracking
   */
  setUser(user: { id: string; email?: string; organizationId?: string } | null): void {
    if (!this.sentryModule) return;

    if (user) {
      this.sentryModule.setUser({
        id: user.id,
        email: user.email,
      });
      this.sentryModule.setTag('organizationId', user.organizationId || 'unknown');
    } else {
      this.sentryModule.setUser(null);
    }
  }

  /**
   * Capture an error with optional context
   */
  captureError(error: Error | unknown, context?: ErrorContext): void {
    // Always log to console
    console.error('[Error]', error, context);

    if (!this.sentryModule) return;

    this.sentryModule.withScope((scope) => {
      if (context?.userId) {
        scope.setUser({ id: context.userId });
      }
      if (context?.organizationId) {
        scope.setTag('organizationId', context.organizationId);
      }
      if (context?.tags) {
        Object.entries(context.tags).forEach(([key, value]) => {
          scope.setTag(key, value);
        });
      }
      if (context?.extra) {
        Object.entries(context.extra).forEach(([key, value]) => {
          scope.setExtra(key, value as Parameters<typeof scope.setExtra>[1]);
        });
      }
      if (context?.componentStack) {
        scope.setExtra('componentStack', context.componentStack);
      }

      this.sentryModule!.captureException(error);
    });
  }

  /**
   * Capture a message (non-error)
   */
  captureMessage(message: string, level: 'info' | 'warning' | 'error' = 'info', extra?: Record<string, unknown>): void {
    // Always log to console
    const logMethod = level === 'error' ? console.error : level === 'warning' ? console.warn : console.info;
    logMethod(`[${level.toUpperCase()}]`, message, extra);

    if (!this.sentryModule) return;

    this.sentryModule.withScope((scope) => {
      if (extra) {
        Object.entries(extra).forEach(([key, value]) => {
          scope.setExtra(key, value as Parameters<typeof scope.setExtra>[1]);
        });
      }
      this.sentryModule!.captureMessage(message, level);
    });
  }

  /**
   * Add breadcrumb for debugging
   */
  addBreadcrumb(breadcrumb: {
    category: string;
    message: string;
    level?: 'info' | 'warning' | 'error';
    data?: Record<string, unknown>;
  }): void {
    if (!this.sentryModule) return;

    this.sentryModule.addBreadcrumb({
      category: breadcrumb.category,
      message: breadcrumb.message,
      level: breadcrumb.level || 'info',
      data: breadcrumb.data,
    });
  }

  /**
   * Check if Sentry is available
   */
  isSentryAvailable(): boolean {
    return this.sentryModule !== null;
  }
}

// Export singleton instance
export const errorTracking = new ErrorTrackingService();

// Initialize on module load (non-blocking)
errorTracking.init().catch(console.error);

// Helper functions for convenience
export function initErrorTracking(): Promise<void> {
  return errorTracking.init();
}

export function captureException(error: Error | unknown, context?: ErrorContext): void {
  errorTracking.captureError(error, context);
}

export function captureError(error: Error | unknown, context?: ErrorContext): void {
  errorTracking.captureError(error, context);
}

export function captureMessage(message: string, level?: 'info' | 'warning' | 'error', extra?: Record<string, unknown>): void {
  errorTracking.captureMessage(message, level, extra);
}

export function setUserForErrorTracking(user: { id: string; email?: string; name?: string; organizationId?: string } | null): void {
  errorTracking.setUser(user ? { id: user.id, email: user.email, organizationId: user.organizationId } : null);
}

// Alias for backward compatibility
export const setErrorTrackingUser = setUserForErrorTracking;

export function clearUserForErrorTracking(): void {
  errorTracking.setUser(null);
}

export function addBreadcrumb(breadcrumb: { category: string; message: string; level?: 'info' | 'warning' | 'error'; data?: Record<string, unknown> }): void {
  errorTracking.addBreadcrumb(breadcrumb);
}
