import { Logger } from '@nestjs/common';
import axios, { AxiosInstance, AxiosRequestConfig } from 'axios';

/**
 * HTTP request result type.
 */
export interface HttpResult<T> {
  data?: T;
  error?: string;
  statusCode?: number;
}

/**
 * Standard connection test result type.
 */
export interface ConnectionTestResult {
  success: boolean;
  message: string;
  details?: Record<string, unknown>;
}

/**
 * Standard sync result type for entity collections.
 */
export interface SyncCollectionResult<T> {
  total: number;
  items: T[];
}

/**
 * Standard sync response type.
 */
export interface SyncResult {
  collectedAt: string;
  errors: string[];
  [key: string]: SyncCollectionResult<unknown> | string | string[];
}

/**
 * Base configuration type for connectors.
 */
export interface BaseConnectorConfig {
  baseUrl?: string;
  apiKey?: string;
  apiToken?: string;
  username?: string;
  password?: string;
  organization?: string;
  timeout?: number;
}

/**
 * Extract error message from unknown error type.
 */
function getErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  if (typeof error === 'string') {
    return error;
  }
  return 'Request failed';
}

/**
 * Base connector class with common HTTP functionality.
 * All integration connectors should extend this for consistent behavior.
 * 
 * @example
 * ```typescript
 * @Injectable()
 * export class MyConnector extends BaseConnector {
 *   constructor() { super('MyConnector'); }
 *   
 *   async testConnection(config: MyConfig): Promise<ConnectionTestResult> {
 *     // Implementation
 *   }
 *   
 *   async sync(config: MyConfig): Promise<SyncResult> {
 *     // Implementation
 *   }
 * }
 * ```
 */
export abstract class BaseConnector {
  protected readonly logger: Logger;
  protected axiosInstance: AxiosInstance;

  constructor(connectorName: string) {
    this.logger = new Logger(connectorName);
    this.axiosInstance = axios.create({
      timeout: 30000,
      validateStatus: (status) => status < 500, // Don't throw on 4xx errors
    });
  }

  /**
   * Make an authenticated GET request.
   */
  protected async get<T = unknown>(
    url: string,
    config?: AxiosRequestConfig,
  ): Promise<HttpResult<T>> {
    try {
      const response = await this.axiosInstance.get<T>(url, config);
      if (response.status >= 400) {
        return {
          error: `HTTP ${response.status}: ${response.statusText}`,
          statusCode: response.status,
        };
      }
      return { data: response.data, statusCode: response.status };
    } catch (error: unknown) {
      const message = getErrorMessage(error);
      this.logger.error(`GET ${url} failed: ${message}`);
      return { error: message };
    }
  }

  /**
   * Make an authenticated POST request.
   */
  protected async post<T = unknown, D = unknown>(
    url: string,
    data?: D,
    config?: AxiosRequestConfig,
  ): Promise<HttpResult<T>> {
    try {
      const response = await this.axiosInstance.post<T>(url, data, config);
      if (response.status >= 400) {
        return {
          error: `HTTP ${response.status}: ${response.statusText}`,
          statusCode: response.status,
        };
      }
      return { data: response.data, statusCode: response.status };
    } catch (error: unknown) {
      const message = getErrorMessage(error);
      this.logger.error(`POST ${url} failed: ${message}`);
      return { error: message };
    }
  }

  /**
   * Make an authenticated PUT request.
   */
  protected async put<T = unknown, D = unknown>(
    url: string,
    data?: D,
    config?: AxiosRequestConfig,
  ): Promise<HttpResult<T>> {
    try {
      const response = await this.axiosInstance.put<T>(url, data, config);
      if (response.status >= 400) {
        return {
          error: `HTTP ${response.status}: ${response.statusText}`,
          statusCode: response.status,
        };
      }
      return { data: response.data, statusCode: response.status };
    } catch (error: unknown) {
      const message = getErrorMessage(error);
      this.logger.error(`PUT ${url} failed: ${message}`);
      return { error: message };
    }
  }

  /**
   * Make an authenticated DELETE request.
   */
  protected async delete<T = unknown>(
    url: string,
    config?: AxiosRequestConfig,
  ): Promise<HttpResult<T>> {
    try {
      const response = await this.axiosInstance.delete<T>(url, config);
      if (response.status >= 400) {
        return {
          error: `HTTP ${response.status}: ${response.statusText}`,
          statusCode: response.status,
        };
      }
      return { data: response.data, statusCode: response.status };
    } catch (error: unknown) {
      const message = getErrorMessage(error);
      this.logger.error(`DELETE ${url} failed: ${message}`);
      return { error: message };
    }
  }

  /**
   * Set default headers (Authorization, Content-Type, etc.).
   */
  protected setHeaders(headers: Record<string, string>): void {
    this.axiosInstance.defaults.headers.common = {
      ...this.axiosInstance.defaults.headers.common,
      ...headers,
    };
  }

  /**
   * Set base URL for all requests.
   */
  protected setBaseURL(baseURL: string): void {
    this.axiosInstance.defaults.baseURL = baseURL;
  }

  /**
   * Create a standard successful connection test result.
   */
  protected successResult(message: string, details?: Record<string, unknown>): ConnectionTestResult {
    return { success: true, message, details };
  }

  /**
   * Create a standard failed connection test result.
   */
  protected failureResult(message: string, details?: Record<string, unknown>): ConnectionTestResult {
    return { success: false, message, details };
  }

  /**
   * Create an empty sync result with errors.
   */
  protected emptySyncResult(errors: string[]): SyncResult {
    return {
      collectedAt: new Date().toISOString(),
      errors,
    };
  }

  /**
   * Create a collection result from items array.
   */
  protected toCollection<T>(items: T[]): SyncCollectionResult<T> {
    return { total: items.length, items };
  }

  /**
   * Abstract methods that must be implemented by subclasses.
   */
  abstract testConnection(config: BaseConnectorConfig): Promise<ConnectionTestResult>;
  abstract sync(config: BaseConnectorConfig): Promise<SyncResult>;
}

