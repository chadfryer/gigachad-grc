import { Logger } from '@nestjs/common';

/**
 * Standard error response structure.
 */
export interface ErrorDetails {
  message: string;
  code?: string;
  statusCode?: number;
  details?: Record<string, unknown>;
  stack?: string;
}

/**
 * Custom error class for domain-specific errors.
 */
export class DomainError extends Error {
  public readonly code: string;
  public readonly statusCode: number;
  public readonly details?: Record<string, unknown>;

  constructor(
    message: string,
    code: string = 'DOMAIN_ERROR',
    statusCode: number = 400,
    details?: Record<string, unknown>,
  ) {
    super(message);
    this.name = 'DomainError';
    this.code = code;
    this.statusCode = statusCode;
    this.details = details;
    Error.captureStackTrace(this, DomainError);
  }
}

/**
 * Error type guard to check if an error is a standard Error object.
 */
export function isError(error: unknown): error is Error {
  return error instanceof Error;
}

/**
 * Error type guard to check if an error is a DomainError.
 */
export function isDomainError(error: unknown): error is DomainError {
  return error instanceof DomainError;
}

/**
 * Error type guard for Prisma errors.
 */
export function isPrismaError(error: unknown): error is Error & { code?: string } {
  return isError(error) && 'code' in error;
}

/**
 * Error type guard for Axios errors.
 */
export function isAxiosError(error: unknown): error is Error & { response?: { status: number; data?: unknown }; code?: string } {
  return isError(error) && ('response' in error || 'code' in error);
}

/**
 * Safely extract error message from unknown error.
 */
export function getErrorMessage(error: unknown): string {
  if (typeof error === 'string') {
    return error;
  }
  if (isError(error)) {
    return error.message;
  }
  if (error && typeof error === 'object' && 'message' in error) {
    return String((error as { message: unknown }).message);
  }
  return 'An unknown error occurred';
}

/**
 * Safely extract error code from unknown error.
 */
export function getErrorCode(error: unknown): string | undefined {
  if (isDomainError(error)) {
    return error.code;
  }
  if (isPrismaError(error)) {
    return error.code;
  }
  if (error && typeof error === 'object' && 'code' in error) {
    return String((error as { code: unknown }).code);
  }
  return undefined;
}

/**
 * Safely extract status code from unknown error.
 */
export function getStatusCode(error: unknown): number {
  if (isDomainError(error)) {
    return error.statusCode;
  }
  if (isAxiosError(error) && error.response?.status) {
    return error.response.status;
  }
  if (error && typeof error === 'object' && 'statusCode' in error) {
    const statusCode = (error as { statusCode: unknown }).statusCode;
    if (typeof statusCode === 'number') {
      return statusCode;
    }
  }
  return 500;
}

/**
 * Convert unknown error to structured ErrorDetails object.
 */
export function toErrorDetails(error: unknown, includeStack = false): ErrorDetails {
  return {
    message: getErrorMessage(error),
    code: getErrorCode(error),
    statusCode: getStatusCode(error),
    details: isDomainError(error) ? error.details : undefined,
    stack: includeStack && isError(error) ? error.stack : undefined,
  };
}

/**
 * Centralized error handler for async operations.
 * Logs the error and returns a standardized error response.
 * 
 * @example
 * ```typescript
 * try {
 *   await someOperation();
 * } catch (error: unknown) {
 *   return handleError(error, this.logger, 'Failed to perform operation');
 * }
 * ```
 */
export function handleError(
  error: unknown,
  logger: Logger,
  context?: string,
  includeStack = process.env.NODE_ENV !== 'production',
): ErrorDetails {
  const errorDetails = toErrorDetails(error, includeStack);
  
  // Log the error with context
  const logMessage = context
    ? `${context}: ${errorDetails.message}`
    : errorDetails.message;

  if (errorDetails.statusCode >= 500) {
    logger.error(logMessage, isError(error) ? error.stack : undefined);
  } else {
    logger.warn(logMessage);
  }

  return errorDetails;
}

/**
 * Wrap an async function with error handling.
 * 
 * @example
 * ```typescript
 * const result = await withErrorHandling(
 *   async () => await riskyOperation(),
 *   this.logger,
 *   'Failed to perform risky operation'
 * );
 * ```
 */
export async function withErrorHandling<T>(
  fn: () => Promise<T>,
  logger: Logger,
  context?: string,
): Promise<T> {
  try {
    return await fn();
  } catch (error: unknown) {
    throw new DomainError(
      getErrorMessage(error),
      getErrorCode(error) || 'OPERATION_FAILED',
      getStatusCode(error),
      { context, originalError: getErrorMessage(error) },
    );
  }
}

/**
 * Create a safe async wrapper that catches errors and returns null.
 * Useful for non-critical operations that shouldn't block the main flow.
 * 
 * @example
 * ```typescript
 * const result = await safeAsync(
 *   () => fetchOptionalData(),
 *   this.logger,
 *   'Optional data fetch failed'
 * );
 * // result is null if operation failed
 * ```
 */
export async function safeAsync<T>(
  fn: () => Promise<T>,
  logger: Logger,
  context?: string,
): Promise<T | null> {
  try {
    return await fn();
  } catch (error: unknown) {
    handleError(error, logger, context);
    return null;
  }
}

/**
 * Retry an async operation with exponential backoff.
 * 
 * @example
 * ```typescript
 * const result = await retryAsync(
 *   () => unreliableOperation(),
 *   { maxRetries: 3, baseDelayMs: 1000 },
 *   this.logger,
 *   'Unreliable operation'
 * );
 * ```
 */
export async function retryAsync<T>(
  fn: () => Promise<T>,
  options: { maxRetries: number; baseDelayMs: number; maxDelayMs?: number },
  logger: Logger,
  context?: string,
): Promise<T> {
  const { maxRetries, baseDelayMs, maxDelayMs = 30000 } = options;
  let lastError: unknown;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error: unknown) {
      lastError = error;
      
      if (attempt < maxRetries) {
        const delayMs = Math.min(baseDelayMs * Math.pow(2, attempt), maxDelayMs);
        logger.warn(`${context || 'Operation'} failed (attempt ${attempt + 1}/${maxRetries + 1}), retrying in ${delayMs}ms...`);
        await new Promise(resolve => setTimeout(resolve, delayMs));
      }
    }
  }

  throw new DomainError(
    getErrorMessage(lastError),
    'RETRY_EXHAUSTED',
    getStatusCode(lastError),
    { context, attempts: maxRetries + 1 },
  );
}
