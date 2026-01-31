/* global __VU */
import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Rate, Trend, Counter, Gauge } from 'k6/metrics';
import { randomIntBetween } from 'https://jslib.k6.io/k6-utils/1.2.0/index.js';
import { BASE_URL, ENDPOINTS, getHeaders, SCENARIOS } from './config.js';

/**
 * Stress Test
 * Tests system behavior under extreme load to find breaking points
 * Run: k6 run tests/load/stress-test.js
 */

// Metrics
const errorRate = new Rate('errors');
const responseTime = new Trend('response_time');
const activeVUs = new Gauge('active_vus');
const requestsPerSecond = new Counter('rps');

export const options = {
  scenarios: {
    stress_test: SCENARIOS.stress,
  },
  thresholds: {
    // More lenient thresholds for stress test - we expect degradation
    http_req_duration: ['p(95)<5000'],  // 95% under 5s
    http_req_failed: ['rate<0.10'],      // Less than 10% errors
    errors: ['rate<0.15'],               // Less than 15% custom errors
  },
  tags: {
    testType: 'stress',
  },
};

// Track system state
let systemHealthy = true;
let degradationStartVUs = 0;
let breakpointVUs = 0;

export default function() {
  const headers = getHeaders();
  activeVUs.add(__VU);
  
  // Mix of read operations to stress the system
  const endpoints = [
    { url: ENDPOINTS.dashboardSummary, name: 'dashboard' },
    { url: ENDPOINTS.controlsList, name: 'controls' },
    { url: ENDPOINTS.frameworksList, name: 'frameworks' },
    { url: ENDPOINTS.risksList, name: 'risks' },
    { url: ENDPOINTS.vendorsList, name: 'vendors' },
    { url: ENDPOINTS.evidenceList, name: 'evidence' },
    { url: ENDPOINTS.integrationsList, name: 'integrations' },
    { url: ENDPOINTS.policiesList, name: 'policies' },
  ];
  
  // Randomly select endpoints to create realistic mixed load
  const selectedEndpoints = endpoints
    .sort(() => Math.random() - 0.5)
    .slice(0, randomIntBetween(3, 6));
  
  group('Stress Test Requests', () => {
    for (const endpoint of selectedEndpoints) {
      const start = Date.now();
      const res = http.get(`${BASE_URL}${endpoint.url}`, { 
        headers,
        tags: { endpoint: endpoint.name },
      });
      const duration = Date.now() - start;
      
      requestsPerSecond.add(1);
      responseTime.add(duration);
      
      const success = check(res, {
        'status is not 5xx': (r) => r.status < 500,
        'response time reasonable': (r) => r.timings.duration < 10000,
      });
      
      errorRate.add(!success);
      
      // Track degradation
      if (!success && systemHealthy) {
        systemHealthy = false;
        degradationStartVUs = __VU;
        console.log(`⚠️ System degradation detected at VU: ${__VU}`);
      }
      
      if (res.status >= 500 && breakpointVUs === 0) {
        breakpointVUs = __VU;
        console.log(`🔴 System breakpoint detected at VU: ${__VU}`);
      }
      
      // Minimal think time during stress
      sleep(randomIntBetween(0.1, 0.5));
    }
  });
  
  // Brief pause between iterations
  sleep(randomIntBetween(0.5, 1));
}

export function handleSummary(data) {
  const { metrics } = data;
  
  const analysis = {
    testType: 'Stress Test',
    timestamp: new Date().toISOString(),
    
    // Traffic summary
    traffic: {
      totalRequests: metrics.http_reqs?.values?.count || 0,
      failedRequests: metrics.http_req_failed?.values?.fails || 0,
      errorRate: ((metrics.errors?.values?.rate || 0) * 100).toFixed(2) + '%',
      peakVUs: metrics.vus?.values?.max || 0,
    },
    
    // Performance under stress
    performance: {
      avgResponseTime: Math.round(metrics.http_req_duration?.values?.avg || 0),
      p50ResponseTime: Math.round(metrics.http_req_duration?.values?.['p(50)'] || 0),
      p90ResponseTime: Math.round(metrics.http_req_duration?.values?.['p(90)'] || 0),
      p95ResponseTime: Math.round(metrics.http_req_duration?.values?.['p(95)'] || 0),
      p99ResponseTime: Math.round(metrics.http_req_duration?.values?.['p(99)'] || 0),
      maxResponseTime: Math.round(metrics.http_req_duration?.values?.max || 0),
    },
    
    // System limits
    limits: {
      degradationStartVUs: degradationStartVUs || 'Not reached',
      breakpointVUs: breakpointVUs || 'Not reached',
    },
    
    // Recommendations
    recommendations: generateRecommendations(metrics),
  };
  
  return {
    'stdout': generateStressReport(analysis),
    'tests/load/results/stress-test-summary.json': JSON.stringify(analysis, null, 2),
  };
}

function generateRecommendations(metrics) {
  const recommendations = [];
  
  const errorRate = (metrics.errors?.values?.rate || 0) * 100;
  const p95 = metrics.http_req_duration?.values?.['p(95)'] || 0;
  const maxVUs = metrics.vus?.values?.max || 0;
  
  if (errorRate > 5) {
    recommendations.push('High error rate detected - consider scaling infrastructure');
  }
  
  if (p95 > 3000) {
    recommendations.push('P95 latency is high - optimize slow endpoints or add caching');
  }
  
  if (breakpointVUs > 0 && breakpointVUs < maxVUs * 0.7) {
    recommendations.push('System breaks early in load ramp - review database connections and resources');
  }
  
  if (recommendations.length === 0) {
    recommendations.push('System handled stress test well - consider higher load targets');
  }
  
  return recommendations;
}

function generateStressReport(analysis) {
  return `
╔══════════════════════════════════════════════════════════════════════╗
║                     STRESS TEST RESULTS                              ║
╠══════════════════════════════════════════════════════════════════════╣
║  Timestamp: ${analysis.timestamp}
╠══════════════════════════════════════════════════════════════════════╣
║  TRAFFIC SUMMARY                                                     ║
╠══════════════════════════════════════════════════════════════════════╣
║  Total Requests:     ${analysis.traffic.totalRequests.toString().padEnd(20)}
║  Failed Requests:    ${analysis.traffic.failedRequests.toString().padEnd(20)}
║  Error Rate:         ${analysis.traffic.errorRate.padEnd(20)}
║  Peak VUs:           ${analysis.traffic.peakVUs.toString().padEnd(20)}
╠══════════════════════════════════════════════════════════════════════╣
║  PERFORMANCE UNDER STRESS (ms)                                       ║
╠══════════════════════════════════════════════════════════════════════╣
║  Average:    ${analysis.performance.avgResponseTime.toString().padEnd(15)}
║  P50:        ${analysis.performance.p50ResponseTime.toString().padEnd(15)}
║  P90:        ${analysis.performance.p90ResponseTime.toString().padEnd(15)}
║  P95:        ${analysis.performance.p95ResponseTime.toString().padEnd(15)}
║  P99:        ${analysis.performance.p99ResponseTime.toString().padEnd(15)}
║  Max:        ${analysis.performance.maxResponseTime.toString().padEnd(15)}
╠══════════════════════════════════════════════════════════════════════╣
║  SYSTEM LIMITS                                                       ║
╠══════════════════════════════════════════════════════════════════════╣
║  Degradation Started at VU:  ${String(analysis.limits.degradationStartVUs).padEnd(10)}
║  System Breakpoint at VU:    ${String(analysis.limits.breakpointVUs).padEnd(10)}
╠══════════════════════════════════════════════════════════════════════╣
║  RECOMMENDATIONS                                                     ║
╠══════════════════════════════════════════════════════════════════════╣
${analysis.recommendations.map(r => `║  • ${r}`).join('\n')}
╚══════════════════════════════════════════════════════════════════════╝
`;
}




