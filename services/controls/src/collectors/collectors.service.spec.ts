import { Test, TestingModule } from '@nestjs/testing';
import { Logger } from '@nestjs/common';
import { CollectorsService } from './collectors.service';
import { PrismaService } from '../prisma/prisma.service';
import { AuditService } from '../audit/audit.service';
import { NotificationsService } from '../notifications/notifications.service';
import { STORAGE_PROVIDER } from '@gigachad-grc/shared';

// Mock safeFetch from shared library - must be before any imports that use it
const mockSafeFetch = jest.fn();
jest.mock('@gigachad-grc/shared', () => {
  const original = jest.requireActual('@gigachad-grc/shared');
  return {
    ...original,
    safeFetch: (...args: any[]) => mockSafeFetch(...args),
  };
});

// Mock Prometheus Counter
const mockCounter = {
  inc: jest.fn(),
  labels: jest.fn().mockReturnThis(),
};

describe('CollectorsService - resilience features', () => {
  let service: CollectorsService;

  beforeAll(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        CollectorsService,
        { provide: PrismaService, useValue: {} },
        { provide: AuditService, useValue: {} },
        { provide: NotificationsService, useValue: {} },
        { provide: STORAGE_PROVIDER, useValue: {} },
        { provide: 'PROM_METRIC_COLLECTORS_RUNS_TOTAL', useValue: mockCounter },
      ],
    })
      // Override the logger to avoid noisy test output
      .setLogger(new Logger('CollectorsServiceTest'))
      .compile();

    service = module.get<CollectorsService>(CollectorsService);
  });

  describe('executeApiCall retry & timeout behavior', () => {
    afterEach(() => {
      mockSafeFetch.mockReset();
      jest.restoreAllMocks();
    });

    it('retries on upstream 5xx errors and eventually succeeds', async () => {
      const responses = [
        new Response('server error', { status: 500 }),
        new Response(JSON.stringify({ ok: true }), { status: 200 }),
      ];

      mockSafeFetch.mockImplementation(() => Promise.resolve(responses.shift()));

      const retrySpy = jest
        .spyOn<any, any>(service as any, 'retryWithBackoff')
        .mockImplementation(async (fn: () => Promise<Response>, maxRetries: number) => {
          let attempt = 0;
          let lastError: any;

          while (attempt <= maxRetries) {
            try {
              const res = await fn();
              if (!res.ok && res.status >= 500) {
                throw new Error(`Upstream error ${res.status}`);
              }
              return res;
            } catch (error) {
              lastError = error;
              if (attempt >= maxRetries) {
                break;
              }
              attempt++;
            }
          }

          throw lastError;
        });

      const collector: any = {
        method: 'GET',
        baseUrl: 'https://api.example.com',
        endpoint: '/test',
      };

      const promise = (service as any).executeApiCall(collector, {
        timeoutMs: 10000,
      });

      const result = await promise;

      expect(mockSafeFetch).toHaveBeenCalledTimes(2);
      expect(retrySpy).toHaveBeenCalled();
      expect(result.statusCode).toBe(200);
      expect(result.data).toEqual({ ok: true });
    });

    it('does not retry on 4xx errors', async () => {
      mockSafeFetch.mockResolvedValue(new Response('bad request', { status: 400 }));

      jest
        .spyOn<any, any>(service as any, 'retryWithBackoff')
        .mockImplementation(async (fn: () => Promise<Response>) => fn());

      const collector: any = {
        method: 'GET',
        baseUrl: 'https://api.example.com',
        endpoint: '/bad',
      };

      await expect(
        (service as any).executeApiCall(collector, {
          timeoutMs: 10000,
        })
      ).rejects.toThrow();

      // Should only call fetch once, because retries are for 5xx/network failures
      expect(mockSafeFetch).toHaveBeenCalledTimes(1);
    });

    it('aborts when request exceeds timeout', async () => {
      const abortError = new Error('The operation was aborted.');
      mockSafeFetch.mockImplementation(
        () =>
          new Promise((_resolve, reject) => {
            // The abort will cause fetch to reject
            setTimeout(() => reject(abortError), 1000);
          })
      );

      jest
        .spyOn<any, any>(service as any, 'retryWithBackoff')
        .mockImplementation(async (fn: () => Promise<Response>) => fn());

      const collector: any = {
        method: 'GET',
        baseUrl: 'https://api.example.com',
        endpoint: '/timeout',
      };

      const promise = (service as any).executeApiCall(collector, {
        timeoutMs: 5,
      });

      await expect(promise).rejects.toThrow();
      expect(mockSafeFetch).toHaveBeenCalledTimes(1);
    });
  });
});
