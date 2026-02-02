import { Injectable, Logger, OnModuleInit } from '@nestjs/common';

/**
 * Service health status
 */
export enum ServiceStatus {
  HEALTHY = 'healthy',
  DEGRADED = 'degraded',
  UNHEALTHY = 'unhealthy',
  UNKNOWN = 'unknown',
}

/**
 * Registered service information
 */
export interface ServiceInfo {
  name: string;
  url: string;
  version?: string;
  status: ServiceStatus;
  lastCheck: Date;
  consecutiveFailures: number;
  metadata?: Record<string, unknown>;
}

/**
 * Service circuit breaker state
 */
export enum ServiceCircuitState {
  CLOSED = 'closed', // Normal operation
  OPEN = 'open', // Failures exceeded threshold, fast-fail
  HALF_OPEN = 'half_open', // Testing if service recovered
}

/**
 * Circuit breaker configuration
 */
export interface CircuitBreakerConfig {
  failureThreshold: number; // Number of failures to trip
  successThreshold: number; // Number of successes to close from half-open
  timeout: number; // MS before moving from open to half-open
}

// Default circuit breaker configuration (used as reference for env var defaults)
const _DEFAULT_CIRCUIT_CONFIG: CircuitBreakerConfig = {
  failureThreshold: 5,
  successThreshold: 2,
  timeout: 30000, // 30 seconds
};

/**
 * Circuit breaker state for a service
 */
interface CircuitBreakerState {
  state: ServiceCircuitState;
  failures: number;
  successes: number;
  lastFailureTime?: Date;
  nextRetryTime?: Date;
}

/**
 * Service Registry for managing microservice discovery and health
 * Implements circuit breaker pattern for fault tolerance
 */
@Injectable()
export class ServiceRegistry implements OnModuleInit {
  private readonly logger = new Logger(ServiceRegistry.name);
  private readonly services = new Map<string, ServiceInfo>();
  private readonly circuitBreakers = new Map<string, CircuitBreakerState>();
  private readonly circuitConfig: CircuitBreakerConfig;
  private healthCheckInterval?: NodeJS.Timeout;

  constructor() {
    this.circuitConfig = {
      failureThreshold: parseInt(process.env.CIRCUIT_FAILURE_THRESHOLD || '5', 10),
      successThreshold: parseInt(process.env.CIRCUIT_SUCCESS_THRESHOLD || '2', 10),
      timeout: parseInt(process.env.CIRCUIT_TIMEOUT_MS || '30000', 10),
    };
  }

  onModuleInit() {
    // Register core services from environment
    this.registerCoreServices();
    
    // Start health check loop
    this.startHealthChecks();
  }

  /**
   * Register core services from environment variables
   */
  private registerCoreServices(): void {
    const coreServices = [
      { name: 'controls', envKey: 'CONTROLS_SERVICE_URL', defaultPort: 3001 },
      { name: 'audit', envKey: 'AUDIT_SERVICE_URL', defaultPort: 3002 },
      { name: 'frameworks', envKey: 'FRAMEWORKS_SERVICE_URL', defaultPort: 3003 },
      { name: 'policies', envKey: 'POLICIES_SERVICE_URL', defaultPort: 3004 },
      { name: 'tprm', envKey: 'TPRM_SERVICE_URL', defaultPort: 3005 },
      { name: 'trust', envKey: 'TRUST_SERVICE_URL', defaultPort: 3006 },
    ];

    for (const svc of coreServices) {
      const url = process.env[svc.envKey] || `http://localhost:${svc.defaultPort}`;
      this.register(svc.name, url);
    }
  }

  /**
   * Register a service
   */
  register(name: string, url: string, metadata?: Record<string, unknown>): void {
    this.services.set(name, {
      name,
      url,
      status: ServiceStatus.UNKNOWN,
      lastCheck: new Date(),
      consecutiveFailures: 0,
      metadata,
    });

    this.circuitBreakers.set(name, {
      state: ServiceCircuitState.CLOSED,
      failures: 0,
      successes: 0,
    });

    this.logger.log(`Registered service: ${name} at ${url}`);
  }

  /**
   * Get service URL with circuit breaker check
   */
  getServiceUrl(name: string): string | null {
    const service = this.services.get(name);
    if (!service) {
      this.logger.warn(`Service not registered: ${name}`);
      return null;
    }

    const circuit = this.circuitBreakers.get(name);
    if (circuit && circuit.state === ServiceCircuitState.OPEN) {
      // Check if we should move to half-open
      if (circuit.nextRetryTime && new Date() >= circuit.nextRetryTime) {
        this.logger.log(`Circuit half-open for: ${name}`);
        circuit.state = ServiceCircuitState.HALF_OPEN;
      } else {
        this.logger.warn(`Circuit open for: ${name}, fast-failing`);
        return null;
      }
    }

    return service.url;
  }

  /**
   * Get service info
   */
  getService(name: string): ServiceInfo | undefined {
    return this.services.get(name);
  }

  /**
   * Get all registered services
   */
  getAllServices(): ServiceInfo[] {
    return Array.from(this.services.values());
  }

  /**
   * Record a successful call to a service
   */
  recordSuccess(name: string): void {
    const circuit = this.circuitBreakers.get(name);
    if (!circuit) return;

    circuit.failures = 0;
    circuit.successes++;

    if (circuit.state === ServiceCircuitState.HALF_OPEN) {
      if (circuit.successes >= this.circuitConfig.successThreshold) {
        this.logger.log(`Circuit closed for: ${name}`);
        circuit.state = ServiceCircuitState.CLOSED;
        circuit.successes = 0;
      }
    }

    const service = this.services.get(name);
    if (service) {
      service.status = ServiceStatus.HEALTHY;
      service.consecutiveFailures = 0;
      service.lastCheck = new Date();
    }
  }

  /**
   * Record a failed call to a service
   */
  recordFailure(name: string): void {
    const circuit = this.circuitBreakers.get(name);
    if (!circuit) return;

    circuit.failures++;
    circuit.successes = 0;
    circuit.lastFailureTime = new Date();

    if (circuit.state === ServiceCircuitState.HALF_OPEN) {
      // Any failure in half-open trips immediately
      this.tripCircuit(name, circuit);
    } else if (circuit.state === ServiceCircuitState.CLOSED) {
      if (circuit.failures >= this.circuitConfig.failureThreshold) {
        this.tripCircuit(name, circuit);
      }
    }

    const service = this.services.get(name);
    if (service) {
      service.consecutiveFailures++;
      service.status = circuit.state === ServiceCircuitState.OPEN
        ? ServiceStatus.UNHEALTHY
        : ServiceStatus.DEGRADED;
      service.lastCheck = new Date();
    }
  }

  /**
   * Trip the circuit breaker
   */
  private tripCircuit(name: string, circuit: CircuitBreakerState): void {
    this.logger.warn(`Circuit opened for: ${name}`);
    circuit.state = ServiceCircuitState.OPEN;
    circuit.nextRetryTime = new Date(Date.now() + this.circuitConfig.timeout);
  }

  /**
   * Get circuit breaker state for a service
   */
  getCircuitState(name: string): ServiceCircuitState | undefined {
    return this.circuitBreakers.get(name)?.state;
  }

  /**
   * Start periodic health checks
   */
  private startHealthChecks(): void {
    const interval = parseInt(process.env.HEALTH_CHECK_INTERVAL_MS || '60000', 10);
    
    this.healthCheckInterval = setInterval(() => {
      this.checkAllServices();
    }, interval);

    // Initial check
    this.checkAllServices();
  }

  /**
   * Check health of all registered services
   */
  private async checkAllServices(): Promise<void> {
    const entries = Array.from(this.services.entries());
    for (const [name, service] of entries) {
      try {
        const response = await fetch(`${service.url}/health`, {
          method: 'GET',
          signal: AbortSignal.timeout(5000),
        });

        if (response.ok) {
          this.recordSuccess(name);
        } else {
          this.recordFailure(name);
        }
      } catch {
        // Service unavailable or timeout
        this.recordFailure(name);
      }
    }
  }

  /**
   * Get health summary
   */
  getHealthSummary(): {
    total: number;
    healthy: number;
    degraded: number;
    unhealthy: number;
    services: ServiceInfo[];
  } {
    const services = this.getAllServices();
    return {
      total: services.length,
      healthy: services.filter((s) => s.status === ServiceStatus.HEALTHY).length,
      degraded: services.filter((s) => s.status === ServiceStatus.DEGRADED).length,
      unhealthy: services.filter((s) => s.status === ServiceStatus.UNHEALTHY).length,
      services,
    };
  }

  /**
   * Cleanup on module destroy
   */
  onModuleDestroy(): void {
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
    }
  }
}
