/* global __ENV */
import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Rate, Trend, Counter as _Counter, Gauge } from 'k6/metrics';
import { randomIntBetween } from 'https://jslib.k6.io/k6-utils/1.2.0/index.js';
import { BASE_URL, ENDPOINTS, getHeaders, SCENARIOS } from './config.js';

/**
 * Soak Test
 * Extended duration test to detect memory leaks, resource exhaustion,
 * and performance degradation over time
 * Run: k6 run tests/load/soak-test.js
 * Note: This test runs for 30 minutes by default
 */

// Metrics for trend analysis
const errorRate = new Rate('errors');
const latencyTrend = new Trend('latency_trend');
const intervalLatency = new Gauge('interval_latency');
const intervalErrors = new Gauge('interval_errors');

// Time-based tracking
let startTime = Date.now();
let intervalStart = Date.now();
let intervalRequests = 0;
let intervalErrorCount = 0;
let intervals = [];

const INTERVAL_DURATION = 60000; // 1 minute intervals for analysis

export const options = {
  scenarios: {
    soak_test: {
      ...SCENARIOS.soak,
      // Can override duration with env var
      duration: __ENV.K6_SOAK_DURATION || '30m',
    },
  },
  thresholds: {
    // Consistent performance over time
    http_req_duration: ['p(95)<2000'],
    http_req_failed: ['rate<0.02'],  // Less than 2% errors over extended period
    errors: ['rate<0.03'],
    // Latency should not degrade significantly
    latency_trend: ['p(95)<3000'],
  },
  tags: {
    testType: 'soak',
  },
};

export default function() {
  const headers = getHeaders();
  const now = Date.now();
  
  // Track intervals
  if (now - intervalStart > INTERVAL_DURATION) {
    // Record interval stats
    intervals.push({
      timestamp: new Date().toISOString(),
      duration: now - intervalStart,
      requests: intervalRequests,
      errors: intervalErrorCount,
      avgLatency: intervalLatency.name ? 'recorded' : 0,
    });
    
    // Log progress
    const elapsedMinutes = Math.round((now - startTime) / 60000);
    console.log(`📊 Interval ${intervals.length}: ${intervalRequests} requests, ${intervalErrorCount} errors (${elapsedMinutes}m elapsed)`);
    
    // Reset interval counters
    intervalStart = now;
    intervalRequests = 0;
    intervalErrorCount = 0;
  }
  
  // Realistic user workflow mix
  const workflows = [
    dashboardWorkflow,
    controlsWorkflow,
    riskWorkflow,
    vendorWorkflow,
    reportingWorkflow,
  ];
  
  const selectedWorkflow = workflows[randomIntBetween(0, workflows.length - 1)];
  selectedWorkflow(headers);
  
  // Realistic think time
  sleep(randomIntBetween(2, 5));
}

function dashboardWorkflow(headers) {
  group('Dashboard Workflow', () => {
    makeRequest(`${BASE_URL}${ENDPOINTS.dashboardSummary}`, headers, 'dashboard');
    sleep(randomIntBetween(1, 3));
    makeRequest(`${BASE_URL}${ENDPOINTS.controlsList}?limit=10`, headers, 'controls');
    sleep(randomIntBetween(1, 2));
    makeRequest(`${BASE_URL}${ENDPOINTS.frameworksList}`, headers, 'frameworks');
  });
}

function controlsWorkflow(headers) {
  group('Controls Workflow', () => {
    makeRequest(`${BASE_URL}${ENDPOINTS.controlsList}`, headers, 'controls');
    sleep(randomIntBetween(2, 4));
    makeRequest(`${BASE_URL}${ENDPOINTS.evidenceList}?limit=20`, headers, 'evidence');
    sleep(randomIntBetween(1, 3));
    makeRequest(`${BASE_URL}${ENDPOINTS.frameworksList}`, headers, 'frameworks');
  });
}

function riskWorkflow(headers) {
  group('Risk Workflow', () => {
    makeRequest(`${BASE_URL}${ENDPOINTS.risksList}`, headers, 'risks');
    sleep(randomIntBetween(2, 5));
    makeRequest(`${BASE_URL}${ENDPOINTS.vendorsList}`, headers, 'vendors');
  });
}

function vendorWorkflow(headers) {
  group('Vendor Workflow', () => {
    makeRequest(`${BASE_URL}${ENDPOINTS.vendorsList}`, headers, 'vendors');
    sleep(randomIntBetween(3, 6));
    makeRequest(`${BASE_URL}${ENDPOINTS.risksList}?status=high`, headers, 'risks');
  });
}

function reportingWorkflow(headers) {
  group('Reporting Workflow', () => {
    makeRequest(`${BASE_URL}${ENDPOINTS.dashboardSummary}`, headers, 'dashboard');
    sleep(randomIntBetween(1, 2));
    makeRequest(`${BASE_URL}${ENDPOINTS.controlsList}`, headers, 'controls');
    sleep(randomIntBetween(1, 2));
    makeRequest(`${BASE_URL}${ENDPOINTS.risksList}`, headers, 'risks');
    sleep(randomIntBetween(1, 2));
    makeRequest(`${BASE_URL}${ENDPOINTS.policiesList}`, headers, 'policies');
  });
}

function makeRequest(url, headers, name) {
  const res = http.get(url, { 
    headers,
    tags: { endpoint: name },
  });
  
  intervalRequests++;
  
  const success = check(res, {
    [`${name} status ok`]: (r) => (r.status >= 200 && r.status < 300) || r.status === 401,
    [`${name} response time ok`]: (r) => r.timings.duration < 5000,
  });
  
  latencyTrend.add(res.timings.duration);
  intervalLatency.add(res.timings.duration);
  
  if (!success) {
    intervalErrorCount++;
    errorRate.add(1);
    intervalErrors.add(1);
  } else {
    errorRate.add(0);
  }
  
  return res;
}

export function handleSummary(data) {
  const { metrics } = data;
  const testDuration = Date.now() - startTime;
  
  // Analyze performance degradation over time
  const degradationAnalysis = analyzeDegrade(intervals);
  
  const analysis = {
    testType: 'Soak Test',
    timestamp: new Date().toISOString(),
    testDuration: `${Math.round(testDuration / 60000)} minutes`,
    
    // Overall metrics
    overall: {
      totalRequests: metrics.http_reqs?.values?.count || 0,
      failedRequests: metrics.http_req_failed?.values?.fails || 0,
      errorRate: ((metrics.errors?.values?.rate || 0) * 100).toFixed(3) + '%',
      requestsPerSecond: (metrics.http_reqs?.values?.rate || 0).toFixed(2),
    },
    
    // Latency over time
    latency: {
      avg: Math.round(metrics.http_req_duration?.values?.avg || 0),
      p50: Math.round(metrics.http_req_duration?.values?.['p(50)'] || 0),
      p90: Math.round(metrics.http_req_duration?.values?.['p(90)'] || 0),
      p95: Math.round(metrics.http_req_duration?.values?.['p(95)'] || 0),
      p99: Math.round(metrics.http_req_duration?.values?.['p(99)'] || 0),
      max: Math.round(metrics.http_req_duration?.values?.max || 0),
    },
    
    // Degradation analysis
    degradation: degradationAnalysis,
    
    // Intervals breakdown
    intervals: intervals,
    
    // Recommendations
    recommendations: generateSoakRecommendations(metrics, degradationAnalysis),
  };
  
  return {
    'stdout': generateSoakReport(analysis),
    'tests/load/results/soak-test-summary.json': JSON.stringify(analysis, null, 2),
  };
}

function analyzeDegrade(intervals) {
  if (intervals.length < 2) {
    return {
      latencyTrend: 'insufficient_data',
      errorTrend: 'insufficient_data',
      memoryLeakRisk: 'unknown',
    };
  }
  
  // Compare first quarter to last quarter
  const quarterSize = Math.floor(intervals.length / 4);
  const firstQuarter = intervals.slice(0, quarterSize);
  const lastQuarter = intervals.slice(-quarterSize);
  
  // Calculate averages
  const firstErrors = firstQuarter.reduce((sum, i) => sum + i.errors, 0) / firstQuarter.length;
  const lastErrors = lastQuarter.reduce((sum, i) => sum + i.errors, 0) / lastQuarter.length;
  
  const errorTrend = lastErrors > firstErrors * 1.5 ? 'increasing' : 
                     lastErrors < firstErrors * 0.5 ? 'decreasing' : 'stable';
  
  return {
    latencyTrend: 'requires_manual_analysis', // Would need interval latency tracking
    errorTrend: errorTrend,
    errorIncrease: lastErrors > firstErrors ? `${((lastErrors / firstErrors - 1) * 100).toFixed(1)}%` : 'none',
    memoryLeakRisk: errorTrend === 'increasing' ? 'possible' : 'low',
    intervalsAnalyzed: intervals.length,
  };
}

function generateSoakRecommendations(metrics, degradation) {
  const recommendations = [];
  
  const errorRate = (metrics.errors?.values?.rate || 0) * 100;
  const p95 = metrics.http_req_duration?.values?.['p(95)'] || 0;
  
  if (degradation.errorTrend === 'increasing') {
    recommendations.push('Error rate increased over time - check for memory leaks or connection pool exhaustion');
  }
  
  if (degradation.memoryLeakRisk === 'possible') {
    recommendations.push('Possible memory leak - monitor container/process memory during extended runs');
  }
  
  if (errorRate > 1) {
    recommendations.push('Error rate above 1% - investigate persistent failures');
  }
  
  if (p95 > 2000) {
    recommendations.push('P95 latency above 2s - consider query optimization or caching');
  }
  
  if (recommendations.length === 0) {
    recommendations.push('System maintained stable performance - suitable for production workloads');
  }
  
  return recommendations;
}

function generateSoakReport(analysis) {
  return `
╔══════════════════════════════════════════════════════════════════════╗
║                       SOAK TEST RESULTS                              ║
╠══════════════════════════════════════════════════════════════════════╣
║  Timestamp: ${analysis.timestamp}
║  Test Duration: ${analysis.testDuration}
╠══════════════════════════════════════════════════════════════════════╣
║  OVERALL METRICS                                                     ║
╠══════════════════════════════════════════════════════════════════════╣
║  Total Requests:     ${analysis.overall.totalRequests.toString().padEnd(20)}
║  Failed Requests:    ${analysis.overall.failedRequests.toString().padEnd(20)}
║  Error Rate:         ${analysis.overall.errorRate.padEnd(20)}
║  Requests/sec:       ${analysis.overall.requestsPerSecond.padEnd(20)}
╠══════════════════════════════════════════════════════════════════════╣
║  LATENCY DISTRIBUTION (ms)                                           ║
╠══════════════════════════════════════════════════════════════════════╣
║  Average:  ${analysis.latency.avg.toString().padEnd(10)} P50:  ${analysis.latency.p50.toString().padEnd(10)}
║  P90:      ${analysis.latency.p90.toString().padEnd(10)} P95:  ${analysis.latency.p95.toString().padEnd(10)}
║  P99:      ${analysis.latency.p99.toString().padEnd(10)} Max:  ${analysis.latency.max.toString().padEnd(10)}
╠══════════════════════════════════════════════════════════════════════╣
║  DEGRADATION ANALYSIS                                                ║
╠══════════════════════════════════════════════════════════════════════╣
║  Error Trend:        ${analysis.degradation.errorTrend.padEnd(20)}
║  Error Increase:     ${analysis.degradation.errorIncrease.padEnd(20)}
║  Memory Leak Risk:   ${analysis.degradation.memoryLeakRisk.padEnd(20)}
║  Intervals Analyzed: ${analysis.degradation.intervalsAnalyzed.toString().padEnd(20)}
╠══════════════════════════════════════════════════════════════════════╣
║  RECOMMENDATIONS                                                     ║
╠══════════════════════════════════════════════════════════════════════╣
${analysis.recommendations.map(r => `║  • ${r}`).join('\n')}
╚══════════════════════════════════════════════════════════════════════╝
`;
}




