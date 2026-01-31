import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Rate, Trend } from 'k6/metrics';
import { BASE_URL, ENDPOINTS, getHeaders, DEFAULT_THRESHOLDS } from './config.js';

/**
 * Smoke Test
 * Quick verification that the system works under minimal load
 * Run: k6 run tests/load/smoke-test.js
 */

// Custom metrics
const errorRate = new Rate('errors');
const apiLatency = new Trend('api_latency');

export const options = {
  vus: 1,
  duration: '30s',
  thresholds: {
    ...DEFAULT_THRESHOLDS,
    errors: ['rate<0.1'],  // Less than 10% errors for smoke test
  },
  tags: {
    testType: 'smoke',
  },
};

export default function() {
  const headers = getHeaders();
  
  group('Health Check', () => {
    const res = http.get(`${BASE_URL}${ENDPOINTS.health}`, { headers });
    
    const success = check(res, {
      'health check status is 200': (r) => r.status === 200,
      'health check response time < 500ms': (r) => r.timings.duration < 500,
    });
    
    errorRate.add(!success);
    apiLatency.add(res.timings.duration);
  });
  
  sleep(1);
  
  group('Dashboard API', () => {
    const res = http.get(`${BASE_URL}${ENDPOINTS.dashboardSummary}`, { headers });
    
    const success = check(res, {
      'dashboard status is 200 or 401': (r) => r.status === 200 || r.status === 401,
      'dashboard response time < 2000ms': (r) => r.timings.duration < 2000,
    });
    
    errorRate.add(!success);
    apiLatency.add(res.timings.duration);
  });
  
  sleep(1);
  
  group('Controls API', () => {
    const res = http.get(`${BASE_URL}${ENDPOINTS.controlsList}`, { headers });
    
    const success = check(res, {
      'controls status is 200 or 401': (r) => r.status === 200 || r.status === 401,
      'controls response time < 2000ms': (r) => r.timings.duration < 2000,
      'controls has valid JSON': (r) => {
        try {
          if (r.status === 200) {
            JSON.parse(r.body);
          }
          return true;
        } catch {
          return false;
        }
      },
    });
    
    errorRate.add(!success);
    apiLatency.add(res.timings.duration);
  });
  
  sleep(1);
  
  group('Frameworks API', () => {
    const res = http.get(`${BASE_URL}${ENDPOINTS.frameworksList}`, { headers });
    
    const success = check(res, {
      'frameworks status is 200 or 401': (r) => r.status === 200 || r.status === 401,
      'frameworks response time < 2000ms': (r) => r.timings.duration < 2000,
    });
    
    errorRate.add(!success);
    apiLatency.add(res.timings.duration);
  });
  
  sleep(1);
  
  group('Integrations API', () => {
    const res = http.get(`${BASE_URL}${ENDPOINTS.integrationsTypes}`, { headers });
    
    const success = check(res, {
      'integrations types status is 200 or 401': (r) => r.status === 200 || r.status === 401,
      'integrations types response time < 1000ms': (r) => r.timings.duration < 1000,
    });
    
    errorRate.add(!success);
    apiLatency.add(res.timings.duration);
  });
  
  sleep(1);
}

export function handleSummary(data) {
  return {
    'stdout': textSummary(data, { indent: ' ', enableColors: true }),
    'tests/load/results/smoke-test-summary.json': JSON.stringify(data),
  };
}

function textSummary(data, _options) {
  const { metrics } = data;
  const lines = [
    '\n========================================',
    '  SMOKE TEST SUMMARY',
    '========================================\n',
    `Total Requests: ${metrics.http_reqs?.values?.count || 0}`,
    `Failed Requests: ${metrics.http_req_failed?.values?.fails || 0}`,
    ``,
    `Response Times:`,
    `  Avg: ${Math.round(metrics.http_req_duration?.values?.avg || 0)}ms`,
    `  Min: ${Math.round(metrics.http_req_duration?.values?.min || 0)}ms`,
    `  Max: ${Math.round(metrics.http_req_duration?.values?.max || 0)}ms`,
    `  P90: ${Math.round(metrics.http_req_duration?.values?.['p(90)'] || 0)}ms`,
    `  P95: ${Math.round(metrics.http_req_duration?.values?.['p(95)'] || 0)}ms`,
    ``,
    `Error Rate: ${((metrics.errors?.values?.rate || 0) * 100).toFixed(2)}%`,
    '\n========================================\n',
  ];
  
  return lines.join('\n');
}




