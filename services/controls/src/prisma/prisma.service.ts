import { Injectable, OnModuleInit, OnModuleDestroy, Logger } from '@nestjs/common';
import { PrismaClient, Prisma } from '@prisma/client';
import { ConfigService } from '@nestjs/config';

/**
 * Configuration for database connection resilience
 */
const DB_RESILIENCE_CONFIG = {
  /** Maximum connection retry attempts */
  maxRetries: 10,
  /** Base delay for exponential backoff (ms) */
  baseDelayMs: 1000,
  /** Maximum delay between retries (ms) */
  maxDelayMs: 30000,
  /** Jitter factor to prevent thundering herd */
  jitterFactor: 0.1,
};

/**
 * Prisma Service with connection pooling and query optimization.
 * 
 * Connection Pool Configuration (via DATABASE_URL):
 * 
 * For high concurrency, append these parameters to your DATABASE_URL:
 * 
 * ?connection_limit=20          - Max connections per service instance
 * &pool_timeout=30              - Seconds to wait for available connection
 * &connect_timeout=10           - Seconds to wait for initial connection
 * &statement_cache_size=100     - Number of prepared statements to cache
 * 
 * Example production DATABASE_URL:
 * postgresql://user:pass@host:5432/db?connection_limit=20&pool_timeout=30&connect_timeout=10
 * 
 * Scaling Guidelines:
 * - For N service replicas, total connections = N * connection_limit
 * - PostgreSQL max_connections should be > total + overhead
 * - Consider PgBouncer for connection pooling at scale (100+ connections)
 */
@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(PrismaService.name);
  private queryCount = 0;
  private slowQueryThresholdMs: number;

  constructor(private configService?: ConfigService) {
    const isDev = process.env.NODE_ENV === 'development';
    const slowQueryThreshold = parseInt(process.env.PRISMA_SLOW_QUERY_MS || '500', 10);

    super({
      log: isDev 
        ? [
            { emit: 'event', level: 'query' },
            { emit: 'stdout', level: 'info' },
            { emit: 'stdout', level: 'warn' },
            { emit: 'stdout', level: 'error' },
          ]
        : [{ emit: 'stdout', level: 'error' }],
      // Datasource configuration happens via DATABASE_URL env var
      // Connection pool settings are part of the URL query string
    });

    this.slowQueryThresholdMs = slowQueryThreshold;

    // Log slow queries in development
    if (isDev) {
      this.setupQueryLogging();
    }
  }

  private setupQueryLogging(): void {
    // @ts-expect-error - Prisma event typing
    this.$on('query', (e: Prisma.QueryEvent) => {
      this.queryCount++;
      
      if (e.duration > this.slowQueryThresholdMs) {
        this.logger.warn(
          `Slow query detected (${e.duration}ms): ${e.query.substring(0, 200)}...`,
        );
      }
    });
  }

  async onModuleInit(): Promise<void> {
    await this.connectWithRetry();
  }

  /**
   * Connect to database with retry logic and exponential backoff.
   * This handles transient connection failures during startup.
   */
  private async connectWithRetry(): Promise<void> {
    const { maxRetries, baseDelayMs, maxDelayMs, jitterFactor } = DB_RESILIENCE_CONFIG;
    
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        this.logger.log(`Connecting to database (attempt ${attempt}/${maxRetries})...`);
        await this.$connect();
        
        this.logger.log('Database connected successfully');
        
        // Log connection pool info if available
        const dbUrl = process.env.DATABASE_URL || '';
        const connectionLimit = dbUrl.match(/connection_limit=(\d+)/)?.[1];
        if (connectionLimit) {
          this.logger.log(`Connection pool limit: ${connectionLimit}`);
        }
        
        return; // Success - exit retry loop
      } catch (error) {
        const isLastAttempt = attempt === maxRetries;
        
        if (isLastAttempt) {
          this.logger.error(
            `Failed to connect to database after ${maxRetries} attempts`,
            error instanceof Error ? error.stack : error
          );
          throw error;
        }
        
        // Calculate delay with exponential backoff + jitter
        const exponentialDelay = baseDelayMs * Math.pow(2, attempt - 1);
        const cappedDelay = Math.min(exponentialDelay, maxDelayMs);
        const jitter = cappedDelay * jitterFactor * Math.random();
        const delay = Math.floor(cappedDelay + jitter);
        
        this.logger.warn(
          `Database connection attempt ${attempt} failed: ${error instanceof Error ? error.message : 'Unknown error'}. ` +
          `Retrying in ${delay}ms...`
        );
        
        await this.sleep(delay);
      }
    }
  }

  /**
   * Sleep utility for retry delays
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  async onModuleDestroy(): Promise<void> {
    this.logger.log(`Disconnecting from database. Total queries executed: ${this.queryCount}`);
    await this.$disconnect();
  }

  /**
   * Helper for soft delete queries - excludes deleted records
   */
  excludeDeleted() {
    return {
      deletedAt: null,
    };
  }

  /**
   * Execute a query with timeout protection
   */
  async withTimeout<T>(
    operation: () => Promise<T>,
    timeoutMs = 30000,
    operationName = 'query',
  ): Promise<T> {
    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(() => {
        reject(new Error(`Database operation '${operationName}' timed out after ${timeoutMs}ms`));
      }, timeoutMs);
    });

    return Promise.race([operation(), timeoutPromise]);
  }

  /**
   * Execute a read-only query (hint for future read replica support)
   * Currently just executes on primary, but can be extended for read replicas
   */
  async readOnly<T>(operation: () => Promise<T>): Promise<T> {
    // TODO: When read replicas are configured, route to replica
    // For now, just execute on primary
    return operation();
  }

  /**
   * Get current query statistics (for monitoring)
   */
  getStats() {
    return {
      totalQueries: this.queryCount,
      slowQueryThresholdMs: this.slowQueryThresholdMs,
    };
  }

  /**
   * Health check for the database connection
   */
  async healthCheck(): Promise<{ status: string; latencyMs: number }> {
    const start = Date.now();
    try {
      await this.$queryRaw`SELECT 1`;
      return {
        status: 'healthy',
        latencyMs: Date.now() - start,
      };
    } catch {
      return {
        status: 'unhealthy',
        latencyMs: Date.now() - start,
      };
    }
  }
}
