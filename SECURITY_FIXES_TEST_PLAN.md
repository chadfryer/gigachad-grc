# Security Fixes Test Plan

This document outlines the testing strategy for all security vulnerability fixes implemented in this release.

---

## 1. CSV Formula Injection Prevention

### Files Modified

- `services/controls/src/exports/exports.service.ts`
- `frontend/src/lib/export.ts`
- `services/trust/src/questionnaires/export.service.ts`

### Unit Tests

- [ ] Test `sanitizeCsvFormula()` prefixes `=` with single quote
- [ ] Test `sanitizeCsvFormula()` prefixes `+` with single quote
- [ ] Test `sanitizeCsvFormula()` prefixes `-` with single quote
- [ ] Test `sanitizeCsvFormula()` prefixes `@` with single quote
- [ ] Test `sanitizeCsvFormula()` prefixes `|` with single quote
- [ ] Test `sanitizeCsvFormula()` prefixes `\t` with single quote
- [ ] Test `sanitizeCsvFormula()` prefixes `\r` with single quote
- [ ] Test normal strings are not modified
- [ ] Test nested objects containing formulas are sanitized

### Integration Tests

- [ ] Export controls to CSV and verify formula characters are escaped
- [ ] Export questionnaires to CSV and verify formula characters are escaped

### UI Tests

- [ ] Download CSV export from controls page
- [ ] Open in Excel and verify no formula execution warnings

---

## 2. Metrics Endpoint Authentication

### Files Created/Modified

- `services/controls/src/common/metrics-auth.middleware.ts` (new)
- `services/controls/src/app.module.ts`

### Unit Tests

- [ ] Test request with valid Bearer token returns 200
- [ ] Test request with invalid Bearer token returns 401
- [ ] Test request with valid Basic Auth returns 200
- [ ] Test request with invalid Basic Auth returns 401
- [ ] Test request from allowed IP returns 200
- [ ] Test request from disallowed IP returns 401
- [ ] Test timing-safe comparison is used (no timing leaks)
- [ ] Test `METRICS_AUTH_DISABLED=true` bypasses auth in dev

### Integration Tests

- [ ] Access `/metrics` without auth - expect 401
- [ ] Access `/metrics` with valid token - expect 200
- [ ] Access `/api/metrics` with valid token - expect 200

---

## 3. SCIM Token Timing Attack Prevention

### Files Modified

- `services/controls/src/scim/scim.controller.ts`

### Unit Tests

- [ ] Test `safeTokenCompare()` returns true for matching tokens
- [ ] Test `safeTokenCompare()` returns false for non-matching tokens
- [ ] Test `safeTokenCompare()` handles different length tokens
- [ ] Test all stored tokens are checked (constant-time iteration)
- [ ] Timing test: verify response time is consistent regardless of match position

### Integration Tests

- [ ] SCIM endpoint rejects invalid token
- [ ] SCIM endpoint accepts valid token

---

## 4. Backup Encryption

### Files Modified

- `deploy/backup.sh`

### Manual Tests

- [ ] Run backup with `BACKUP_ENCRYPT_ENABLED=true` - verify `.tar.gz.enc` created
- [ ] Run backup with `BACKUP_ENCRYPT_ENABLED=false` - verify `.tar.gz` created
- [ ] Verify encrypted backup cannot be extracted without key
- [ ] Verify encrypted backup can be decrypted with correct key
- [ ] Verify unencrypted backup is deleted after encryption

### Script Tests

- [ ] Test `encrypt_archive()` function with valid key
- [ ] Test encryption fails gracefully if key too short
- [ ] Test manifest includes encryption metadata

---

## 5. Webhook Replay Attack Prevention

### Files Modified

- `services/controls/src/webhooks/webhooks.service.ts`
- `services/audit/src/fieldguide/fieldguide.service.ts`

### Unit Tests

- [ ] Test `signWebhookPayload()` includes timestamp in signature
- [ ] Test `X-Webhook-Timestamp` header is set
- [ ] Test `verifyWebhookSignature()` accepts valid signature within time window
- [ ] Test `verifyWebhookSignature()` rejects expired signatures (>5 min old)
- [ ] Test `verifyWebhookSignature()` rejects invalid signatures
- [ ] Test legacy signature format still works (backward compatibility)

### Integration Tests

- [ ] Trigger webhook and verify signature format
- [ ] Replay old webhook request - expect rejection

---

## 6. OAuth Redirect URI Validation

### Files Modified

- `services/controls/src/integrations/jira/jira.service.ts`
- `services/controls/src/integrations/servicenow/servicenow.service.ts`

### Unit Tests

- [ ] Test `validateRedirectUri()` accepts allowed origins
- [ ] Test `validateRedirectUri()` rejects disallowed origins
- [ ] Test `validateRedirectUri()` rejects malformed URLs
- [ ] Test `validateRedirectUri()` rejects `javascript:` URLs
- [ ] Test `validateRedirectUri()` rejects `data:` URLs
- [ ] Test validation runs in `getOAuthUrl()`
- [ ] Test validation runs in `handleOAuthCallback()`

### Integration Tests

- [ ] OAuth flow with valid redirect URI succeeds
- [ ] OAuth flow with invalid redirect URI fails with 400

---

## 7. Export Endpoint Role Guards

### Files Modified

- `services/controls/src/exports/exports.controller.ts`

### Unit Tests

- [ ] Test `listExportJobs` requires admin/compliance_manager/auditor role
- [ ] Test `getExportJob` requires admin/compliance_manager/auditor role
- [ ] Test `downloadExport` requires admin/compliance_manager/auditor role
- [ ] Test `cancelExportJob` requires admin/compliance_manager/auditor role
- [ ] Test regular user cannot access export endpoints

### Integration Tests

- [ ] Admin can list exports
- [ ] Regular user receives 403 on export endpoints

---

## 8. Audit Log Access Control

### Files Modified

- `services/controls/src/audit/audit.controller.ts`

### Unit Tests

- [ ] Test controller has `@Roles('admin', 'auditor')` decorator
- [ ] Test `RolesGuard` is applied
- [ ] Test rate limit is applied to export endpoint

### Integration Tests

- [ ] Admin can access audit logs
- [ ] Auditor can access audit logs
- [ ] Regular user receives 403

---

## 9. Email Header/HTML Injection Prevention

### Files Modified

- `services/controls/src/email/email.service.ts`
- `services/controls/src/email/email-templates.service.ts`

### Unit Tests

- [ ] Test `sanitizeHeader()` removes `\r` characters
- [ ] Test `sanitizeHeader()` removes `\n` characters
- [ ] Test `sanitizeHeader()` trims whitespace
- [ ] Test `encodeHtml()` escapes `<` to `&lt;`
- [ ] Test `encodeHtml()` escapes `>` to `&gt;`
- [ ] Test `encodeHtml()` escapes `&` to `&amp;`
- [ ] Test `encodeHtml()` escapes `"` to `&quot;`
- [ ] Test `encodeHtml()` escapes `'` to `&#x27;`
- [ ] Test `sanitizeUrl()` blocks `javascript:` URLs
- [ ] Test `sanitizeUrl()` blocks `data:` URLs
- [ ] Test email templates use encoded values

### Integration Tests

- [ ] Send email with malicious header - verify sanitized
- [ ] Send email with HTML in content - verify encoded

---

## 10. Slack Message Injection Prevention

### Files Modified

- `services/controls/src/notifications/slack.service.ts`

### Unit Tests

- [ ] Test `escapeSlackMrkdwn()` escapes `&` to `&amp;`
- [ ] Test `escapeSlackMrkdwn()` escapes `<` to `&lt;`
- [ ] Test `escapeSlackMrkdwn()` escapes `>` to `&gt;`
- [ ] Test `escapeSlackMrkdwn()` escapes `*` to `\*`
- [ ] Test `escapeSlackMrkdwn()` escapes `_` to `\_`
- [ ] Test `escapeSlackMrkdwn()` escapes backticks
- [ ] Test task notifications use escaped values

### Integration Tests

- [ ] Send Slack notification with special characters - verify escaped

---

## 11. File Upload Interceptor

### Files Created/Modified

- `services/controls/src/common/file-upload.interceptor.ts` (new)
- `services/controls/src/common/file-validator.service.ts`

### Unit Tests

- [ ] Test interceptor extracts single file from request
- [ ] Test interceptor extracts multiple files from request
- [ ] Test interceptor validates file against category rules
- [ ] Test interceptor rejects files exceeding size limit
- [ ] Test interceptor rejects disallowed MIME types
- [ ] Test `@FileUpload` decorator sets metadata correctly
- [ ] Test custom options override defaults

### Integration Tests

- [ ] Upload valid file - expect success
- [ ] Upload oversized file - expect 400
- [ ] Upload disallowed file type - expect 400

---

## 12. Audit Log Integrity (HMAC Signing)

### Files Modified

- `services/controls/src/audit/audit.service.ts`

### Unit Tests

- [ ] Test `generateLogSignature()` produces consistent signatures
- [ ] Test `generateLogSignature()` includes previous hash in calculation
- [ ] Test `verifyLogIntegrity()` validates correct signatures
- [ ] Test `verifyLogIntegrity()` detects tampered logs
- [ ] Test `verifyAuditLogIntegrity()` detects chain breaks
- [ ] Test signing is skipped when `AUDIT_LOG_HMAC_KEY` not set
- [ ] Test log entries include hash in metadata

### Integration Tests

- [ ] Create audit log entry - verify signature in metadata
- [ ] Verify audit log chain for organization

---

## 13. Security Event Alerting

### Files Modified

- `services/controls/src/audit/security-audit.service.ts`

### Unit Tests

- [ ] Test `sendSecurityAlert()` sends Slack webhook for high severity
- [ ] Test `sendSecurityAlert()` respects threshold setting
- [ ] Test `trackFailedAttempt()` increments count
- [ ] Test brute force detection triggers at threshold
- [ ] Test failed attempt tracking cleans up old entries
- [ ] Test alert message formatting

### Integration Tests

- [ ] Log high severity event - verify Slack alert sent
- [ ] Simulate brute force - verify detection and alert

---

## 14. Malware Scanning

### Files Created

- `services/controls/src/common/malware-scanner.service.ts` (new)

### Unit Tests

- [ ] Test `scanFile()` returns clean result when disabled
- [ ] Test `scanFile()` skips files exceeding size limit
- [ ] Test `calculateHash()` produces correct SHA-256
- [ ] Test `scanWithClamAV()` detects clean files
- [ ] Test `scanWithClamAV()` detects infected files
- [ ] Test `scanWithVirusTotal()` hash lookup works
- [ ] Test `getStatus()` reports scanner availability

### Integration Tests (requires ClamAV)

- [ ] Scan clean file - expect clean result
- [ ] Scan EICAR test file - expect detection

---

## 15. Backup Signature Verification

### Files Modified

- `deploy/backup.sh`
- `deploy/restore.sh`

### Manual Tests

- [ ] Run backup with `BACKUP_SIGNING_KEY` set - verify `.sig` file created
- [ ] Run restore with valid signature - expect success
- [ ] Run restore with tampered backup - expect failure
- [ ] Run restore with `BACKUP_SIGNATURE_REQUIRED=true` and no signature - expect failure
- [ ] Run restore without `BACKUP_SIGNING_KEY` - expect warning

### Script Tests

- [ ] Test `generate_backup_signature()` creates valid JSON
- [ ] Test `verify_backup_signature()` validates correct signature
- [ ] Test signature contains expected metadata

---

## Test Execution Order

1. **Unit Tests First** - Run all unit tests to validate individual functions
2. **Integration Tests** - Run integration tests to validate component interaction
3. **Manual/UI Tests** - Perform manual verification in the running application
4. **Security Scans** - Run static analysis tools (Semgrep, ESLint security rules)

## Success Criteria

- All unit tests pass
- All integration tests pass
- No regressions in existing functionality
- Security scan reports no new vulnerabilities
- Manual verification confirms fixes work as expected
