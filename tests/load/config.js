/* global __ENV */
/**
 * k6 Load Testing Configuration for GigaChad GRC
 * 
 * Environment Variables:
 *   K6_BASE_URL - Base URL of the application (default: http://localhost:3001)
 *   K6_API_TOKEN - API token for authenticated requests
 *   K6_VUS - Number of virtual users (default varies by test type)
 *   K6_DURATION - Test duration (default varies by test type)
 */

// Base configuration
export const BASE_URL = __ENV.K6_BASE_URL || 'http://localhost:3001';
export const API_TOKEN = __ENV.K6_API_TOKEN || '';

// Thresholds - Define acceptable performance limits
export const DEFAULT_THRESHOLDS = {
  // Response time thresholds
  http_req_duration: [
    'p(50)<500',    // 50% of requests under 500ms
    'p(90)<1000',   // 90% of requests under 1s
    'p(95)<2000',   // 95% of requests under 2s
    'p(99)<5000',   // 99% of requests under 5s
  ],
  // Error rate threshold
  http_req_failed: ['rate<0.01'],  // Less than 1% error rate
  // Request rate
  http_reqs: ['rate>10'],  // At least 10 requests per second
};

// Strict thresholds for critical endpoints
export const STRICT_THRESHOLDS = {
  http_req_duration: [
    'p(50)<200',
    'p(90)<500',
    'p(95)<1000',
    'p(99)<2000',
  ],
  http_req_failed: ['rate<0.001'],  // Less than 0.1% error rate
};

// Test scenarios
export const SCENARIOS = {
  // Smoke test - Quick verification
  smoke: {
    executor: 'constant-vus',
    vus: 1,
    duration: '30s',
  },
  
  // Load test - Normal expected load
  load: {
    executor: 'ramping-vus',
    startVUs: 0,
    stages: [
      { duration: '2m', target: 50 },   // Ramp up to 50 users
      { duration: '5m', target: 50 },   // Stay at 50 users
      { duration: '2m', target: 100 },  // Ramp up to 100 users
      { duration: '5m', target: 100 },  // Stay at 100 users
      { duration: '2m', target: 0 },    // Ramp down to 0
    ],
  },
  
  // Stress test - Beyond normal capacity
  stress: {
    executor: 'ramping-vus',
    startVUs: 0,
    stages: [
      { duration: '2m', target: 100 },
      { duration: '5m', target: 100 },
      { duration: '2m', target: 200 },
      { duration: '5m', target: 200 },
      { duration: '2m', target: 300 },
      { duration: '5m', target: 300 },
      { duration: '2m', target: 0 },
    ],
  },
  
  // Spike test - Sudden traffic spikes
  spike: {
    executor: 'ramping-vus',
    startVUs: 0,
    stages: [
      { duration: '30s', target: 10 },   // Normal load
      { duration: '10s', target: 500 },  // Spike!
      { duration: '1m', target: 500 },   // Stay at spike
      { duration: '10s', target: 10 },   // Back to normal
      { duration: '2m', target: 10 },    // Recovery period
      { duration: '30s', target: 0 },    // Ramp down
    ],
  },
  
  // Soak test - Extended duration for memory leaks
  soak: {
    executor: 'constant-vus',
    vus: 50,
    duration: '30m',
  },
  
  // Breakpoint test - Find system limits
  breakpoint: {
    executor: 'ramping-arrival-rate',
    startRate: 10,
    timeUnit: '1s',
    preAllocatedVUs: 500,
    maxVUs: 1000,
    stages: [
      { duration: '2m', target: 50 },
      { duration: '2m', target: 100 },
      { duration: '2m', target: 200 },
      { duration: '2m', target: 300 },
      { duration: '2m', target: 400 },
      { duration: '2m', target: 500 },
    ],
  },
};

// API Endpoints to test
export const ENDPOINTS = {
  // Public endpoints
  health: '/health',
  
  // Dashboard
  dashboardSummary: '/api/dashboard/summary',
  
  // Controls
  controlsList: '/api/controls',
  controlsById: (id) => `/api/controls/${id}`,
  
  // Frameworks
  frameworksList: '/api/frameworks',
  frameworksById: (id) => `/api/frameworks/${id}`,
  
  // Risks
  risksList: '/api/risks',
  risksById: (id) => `/api/risks/${id}`,
  
  // Policies
  policiesList: '/api/policies',
  policiesById: (id) => `/api/policies/${id}`,
  
  // Vendors
  vendorsList: '/api/vendors',
  vendorsById: (id) => `/api/vendors/${id}`,
  
  // Evidence
  evidenceList: '/api/evidence',
  evidenceById: (id) => `/api/evidence/${id}`,
  
  // Integrations
  integrationsList: '/api/integrations',
  integrationsTypes: '/api/integrations/types',
  
  // Users
  usersList: '/api/users',
  usersMe: '/api/users/me',
  
  // Audits
  auditsList: '/api/audits',
};

// Common headers
export function getHeaders() {
  const headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
  };
  
  if (API_TOKEN) {
    headers['Authorization'] = `Bearer ${API_TOKEN}`;
  }
  
  return headers;
}

// Tag groups for metrics organization
export const TAGS = {
  dashboard: { name: 'dashboard', type: 'api' },
  controls: { name: 'controls', type: 'api' },
  frameworks: { name: 'frameworks', type: 'api' },
  risks: { name: 'risks', type: 'api' },
  policies: { name: 'policies', type: 'api' },
  vendors: { name: 'vendors', type: 'api' },
  evidence: { name: 'evidence', type: 'api' },
  integrations: { name: 'integrations', type: 'api' },
  users: { name: 'users', type: 'api' },
  audits: { name: 'audits', type: 'api' },
};




