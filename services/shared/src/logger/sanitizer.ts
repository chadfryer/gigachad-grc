/**
 * Logging Sanitizer - Removes or masks sensitive data from log output
 *
 * Use this module to sanitize data before logging to prevent
 * sensitive information from appearing in log files.
 */

// List of keys that should always be redacted
const SENSITIVE_KEYS = [
  'password',
  'secret',
  'token',
  'apiKey',
  'api_key',
  'apikey',
  'credential',
  'accessToken',
  'access_token',
  'refreshToken',
  'refresh_token',
  'authorization',
  'bearer',
  'privateKey',
  'private_key',
  'clientSecret',
  'client_secret',
];

/**
 * Masks an email address for safe logging
 * Example: "john.doe@example.com" -> "joh***@***"
 */
export function maskEmail(email: string): string {
  if (!email || typeof email !== 'string') return email;
  const atIndex = email.indexOf('@');
  if (atIndex < 1) return '[INVALID EMAIL]';
  const prefix = email.substring(0, Math.min(3, atIndex));
  return `${prefix}***@***`;
}

/**
 * Sanitizes a string value by redacting sensitive patterns
 */
function sanitizeString(value: string): string {
  // SECURITY: Limit input length to prevent ReDoS attacks
  const MAX_SANITIZE_LENGTH = 100_000; // 100KB limit
  const input =
    value.length > MAX_SANITIZE_LENGTH
      ? value.substring(0, MAX_SANITIZE_LENGTH) + '[TRUNCATED]'
      : value;

  // SECURITY: Input length bounded above to prevent polynomial ReDoS
  return (
    input
      // Redact email addresses - using simpler pattern to avoid backtracking
      .replace(
        /[a-zA-Z0-9._-]{1,64}@[a-zA-Z0-9._-]{1,255}\.[a-zA-Z0-9_-]{1,63}/gi,
        '[EMAIL REDACTED]'
      )
      // Redact Bearer tokens (JWT format)
      .replace(
        /(Bearer\s+)[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*/gi,
        '$1[TOKEN REDACTED]'
      )
      // Redact standalone JWT tokens
      .replace(/\beyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+/g, '[JWT REDACTED]')
      // Redact sensitive key-value pairs - using bounded quantifiers
      .replace(
        /(password|secret|apikey|api_key|token|credential|authorization)['":\s]{0,10}[=:]["']?[^"'\s,}]{0,1000}/gi,
        '$1: [REDACTED]'
      )
  );
}

/**
 * Checks if a key name indicates sensitive data
 */
function isSensitiveKey(key: string): boolean {
  const lowerKey = key.toLowerCase();
  return SENSITIVE_KEYS.some((sk) => lowerKey.includes(sk.toLowerCase()));
}

/**
 * Sanitizes any data structure for safe logging
 *
 * - Strings: Redacts emails, tokens, and sensitive patterns
 * - Objects: Recursively sanitizes, redacting sensitive keys
 * - Arrays: Recursively sanitizes each element
 * - Primitives: Returned as-is
 *
 * @param data - The data to sanitize
 * @returns Sanitized copy of the data
 */
export function sanitizeForLogging(data: unknown): unknown {
  if (data === null || data === undefined) {
    return data;
  }

  if (typeof data === 'string') {
    return sanitizeString(data);
  }

  if (typeof data === 'object') {
    // Handle Error objects specially
    if (data instanceof Error) {
      return {
        name: data.name,
        message: sanitizeString(data.message),
        // Only include stack in non-production for debugging
        ...(process.env.NODE_ENV !== 'production' && data.stack
          ? { stack: sanitizeString(data.stack) }
          : {}),
      };
    }

    // Handle arrays
    if (Array.isArray(data)) {
      return data.map((item) => sanitizeForLogging(item));
    }

    // Handle plain objects
    const sanitized: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(data)) {
      if (isSensitiveKey(key)) {
        sanitized[key] = '[REDACTED]';
      } else if (key.toLowerCase() === 'email' && typeof value === 'string') {
        sanitized[key] = maskEmail(value);
      } else if (typeof value === 'object' && value !== null) {
        sanitized[key] = sanitizeForLogging(value);
      } else if (typeof value === 'string') {
        sanitized[key] = sanitizeString(value);
      } else {
        sanitized[key] = value;
      }
    }
    return sanitized;
  }

  return data;
}

/**
 * Sanitizes error objects for logging
 * In production, only returns the message (no stack trace)
 * In development, includes sanitized stack trace
 */
export function sanitizeError(error: Error | unknown): { message: string; stack?: string } {
  if (error instanceof Error) {
    const result: { message: string; stack?: string } = {
      message: sanitizeString(error.message),
    };

    // Only include stack trace in non-production environments
    if (process.env.NODE_ENV !== 'production' && error.stack) {
      result.stack = sanitizeString(error.stack);
    }

    return result;
  }

  return {
    message: typeof error === 'string' ? sanitizeString(error) : 'Unknown error',
  };
}

/**
 * Creates a logging-safe user identifier from an email
 * Use this instead of logging full email addresses
 */
export function safeUserId(email: string | undefined | null): string {
  if (!email) return '[no email]';
  return maskEmail(email);
}
