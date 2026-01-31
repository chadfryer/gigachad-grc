import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';
import { randomIntBetween } from 'https://jslib.k6.io/k6-utils/1.2.0/index.js';
import { BASE_URL, ENDPOINTS, getHeaders, DEFAULT_THRESHOLDS, SCENARIOS } from './config.js';

/**
 * API Load Test
 * Tests all major API endpoints under realistic load
 * Run: k6 run tests/load/api-load-test.js
 * Run with custom VUs: k6 run --vus 50 --duration 5m tests/load/api-load-test.js
 */

// Custom metrics by endpoint
const dashboardLatency = new Trend('dashboard_latency');
const controlsLatency = new Trend('controls_latency');
const frameworksLatency = new Trend('frameworks_latency');
const risksLatency = new Trend('risks_latency');
const policiesLatency = new Trend('policies_latency');
const vendorsLatency = new Trend('vendors_latency');
const evidenceLatency = new Trend('evidence_latency');
const integrationsLatency = new Trend('integrations_latency');

const errorRate = new Rate('errors');
const successfulRequests = new Counter('successful_requests');
const failedRequests = new Counter('failed_requests');

export const options = {
  scenarios: {
    load_test: SCENARIOS.load,
  },
  thresholds: {
    ...DEFAULT_THRESHOLDS,
    dashboard_latency: ['p(95)<2000'],
    controls_latency: ['p(95)<2000'],
    frameworks_latency: ['p(95)<2000'],
    risks_latency: ['p(95)<2000'],
    policies_latency: ['p(95)<2000'],
    vendors_latency: ['p(95)<2000'],
    evidence_latency: ['p(95)<2000'],
    integrations_latency: ['p(95)<1000'],
    errors: ['rate<0.05'],  // Less than 5% error rate
  },
  tags: {
    testType: 'load',
  },
};

// Simulated user workflows
const WORKFLOWS = {
  // GRC Analyst reviewing compliance
  complianceReview: () => {
    const headers = getHeaders();
    
    group('Compliance Review Workflow', () => {
      // Check dashboard
      let res = http.get(`${BASE_URL}${ENDPOINTS.dashboardSummary}`, { headers });
      checkResponse(res, 'dashboard', dashboardLatency);
      sleep(randomIntBetween(1, 3));
      
      // View frameworks
      res = http.get(`${BASE_URL}${ENDPOINTS.frameworksList}`, { headers });
      checkResponse(res, 'frameworks', frameworksLatency);
      sleep(randomIntBetween(2, 5));
      
      // Check controls
      res = http.get(`${BASE_URL}${ENDPOINTS.controlsList}`, { headers });
      checkResponse(res, 'controls', controlsLatency);
      sleep(randomIntBetween(2, 4));
      
      // Review evidence
      res = http.get(`${BASE_URL}${ENDPOINTS.evidenceList}`, { headers });
      checkResponse(res, 'evidence', evidenceLatency);
    });
  },
  
  // Risk manager assessing risks
  riskAssessment: () => {
    const headers = getHeaders();
    
    group('Risk Assessment Workflow', () => {
      // View risks
      let res = http.get(`${BASE_URL}${ENDPOINTS.risksList}`, { headers });
      checkResponse(res, 'risks', risksLatency);
      sleep(randomIntBetween(2, 4));
      
      // Check vendors
      res = http.get(`${BASE_URL}${ENDPOINTS.vendorsList}`, { headers });
      checkResponse(res, 'vendors', vendorsLatency);
      sleep(randomIntBetween(2, 5));
      
      // Review controls
      res = http.get(`${BASE_URL}${ENDPOINTS.controlsList}`, { headers });
      checkResponse(res, 'controls', controlsLatency);
    });
  },
  
  // Admin checking system status
  adminCheck: () => {
    const headers = getHeaders();
    
    group('Admin Check Workflow', () => {
      // Dashboard
      let res = http.get(`${BASE_URL}${ENDPOINTS.dashboardSummary}`, { headers });
      checkResponse(res, 'dashboard', dashboardLatency);
      sleep(randomIntBetween(1, 2));
      
      // Integrations
      res = http.get(`${BASE_URL}${ENDPOINTS.integrationsList}`, { headers });
      checkResponse(res, 'integrations', integrationsLatency);
      sleep(randomIntBetween(1, 3));
      
      // Users
      res = http.get(`${BASE_URL}${ENDPOINTS.usersList}`, { headers });
      checkResponse(res, 'users', dashboardLatency);
    });
  },
  
  // Policy manager reviewing policies
  policyReview: () => {
    const headers = getHeaders();
    
    group('Policy Review Workflow', () => {
      // View policies
      let res = http.get(`${BASE_URL}${ENDPOINTS.policiesList}`, { headers });
      checkResponse(res, 'policies', policiesLatency);
      sleep(randomIntBetween(3, 6));
      
      // Check controls mapping
      res = http.get(`${BASE_URL}${ENDPOINTS.controlsList}`, { headers });
      checkResponse(res, 'controls', controlsLatency);
    });
  },
};

function checkResponse(res, name, latencyMetric) {
  const success = check(res, {
    [`${name} status is 2xx or 401`]: (r) => (r.status >= 200 && r.status < 300) || r.status === 401,
    [`${name} response time < 5000ms`]: (r) => r.timings.duration < 5000,
  });
  
  latencyMetric.add(res.timings.duration);
  errorRate.add(!success);
  
  if (success) {
    successfulRequests.add(1);
  } else {
    failedRequests.add(1);
  }
  
  return success;
}

export default function() {
  // Randomly select a workflow to simulate realistic usage patterns
  const workflows = Object.values(WORKFLOWS);
  const selectedWorkflow = workflows[randomIntBetween(0, workflows.length - 1)];
  selectedWorkflow();
  
  // Think time between workflows
  sleep(randomIntBetween(2, 5));
}

export function handleSummary(data) {
  const { metrics } = data;
  
  const summary = {
    testType: 'API Load Test',
    timestamp: new Date().toISOString(),
    summary: {
      totalRequests: metrics.http_reqs?.values?.count || 0,
      failedRequests: metrics.http_req_failed?.values?.fails || 0,
      errorRate: ((metrics.errors?.values?.rate || 0) * 100).toFixed(2) + '%',
      requestsPerSecond: (metrics.http_reqs?.values?.rate || 0).toFixed(2),
    },
    latency: {
      avg: Math.round(metrics.http_req_duration?.values?.avg || 0),
      min: Math.round(metrics.http_req_duration?.values?.min || 0),
      max: Math.round(metrics.http_req_duration?.values?.max || 0),
      p50: Math.round(metrics.http_req_duration?.values?.['p(50)'] || 0),
      p90: Math.round(metrics.http_req_duration?.values?.['p(90)'] || 0),
      p95: Math.round(metrics.http_req_duration?.values?.['p(95)'] || 0),
      p99: Math.round(metrics.http_req_duration?.values?.['p(99)'] || 0),
    },
    endpointLatency: {
      dashboard: Math.round(metrics.dashboard_latency?.values?.avg || 0),
      controls: Math.round(metrics.controls_latency?.values?.avg || 0),
      frameworks: Math.round(metrics.frameworks_latency?.values?.avg || 0),
      risks: Math.round(metrics.risks_latency?.values?.avg || 0),
      policies: Math.round(metrics.policies_latency?.values?.avg || 0),
      vendors: Math.round(metrics.vendors_latency?.values?.avg || 0),
      evidence: Math.round(metrics.evidence_latency?.values?.avg || 0),
      integrations: Math.round(metrics.integrations_latency?.values?.avg || 0),
    },
    thresholds: data.thresholds,
  };
  
  return {
    'stdout': generateTextReport(summary, metrics),
    'tests/load/results/api-load-test-summary.json': JSON.stringify(summary, null, 2),
  };
}

function generateTextReport(summary, _metrics) {
  return `
╔══════════════════════════════════════════════════════════════════════╗
║                     API LOAD TEST RESULTS                            ║
╠══════════════════════════════════════════════════════════════════════╣
║  Timestamp: ${summary.timestamp}
╠══════════════════════════════════════════════════════════════════════╣
║  SUMMARY                                                             ║
╠══════════════════════════════════════════════════════════════════════╣
║  Total Requests:     ${summary.summary.totalRequests.toString().padEnd(20)}
║  Failed Requests:    ${summary.summary.failedRequests.toString().padEnd(20)}
║  Error Rate:         ${summary.summary.errorRate.padEnd(20)}
║  Requests/sec:       ${summary.summary.requestsPerSecond.padEnd(20)}
╠══════════════════════════════════════════════════════════════════════╣
║  RESPONSE TIME (ms)                                                  ║
╠══════════════════════════════════════════════════════════════════════╣
║  Average:  ${summary.latency.avg.toString().padEnd(10)} P50:  ${summary.latency.p50.toString().padEnd(10)}
║  Min:      ${summary.latency.min.toString().padEnd(10)} P90:  ${summary.latency.p90.toString().padEnd(10)}
║  Max:      ${summary.latency.max.toString().padEnd(10)} P95:  ${summary.latency.p95.toString().padEnd(10)}
║                        P99:  ${summary.latency.p99.toString().padEnd(10)}
╠══════════════════════════════════════════════════════════════════════╣
║  ENDPOINT LATENCY (avg ms)                                           ║
╠══════════════════════════════════════════════════════════════════════╣
║  Dashboard:     ${summary.endpointLatency.dashboard.toString().padEnd(10)}
║  Controls:      ${summary.endpointLatency.controls.toString().padEnd(10)}
║  Frameworks:    ${summary.endpointLatency.frameworks.toString().padEnd(10)}
║  Risks:         ${summary.endpointLatency.risks.toString().padEnd(10)}
║  Policies:      ${summary.endpointLatency.policies.toString().padEnd(10)}
║  Vendors:       ${summary.endpointLatency.vendors.toString().padEnd(10)}
║  Evidence:      ${summary.endpointLatency.evidence.toString().padEnd(10)}
║  Integrations:  ${summary.endpointLatency.integrations.toString().padEnd(10)}
╚══════════════════════════════════════════════════════════════════════╝
`;
}




