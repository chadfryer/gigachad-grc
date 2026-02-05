# CI Security Pipeline

This document describes the security scanning infrastructure integrated into our CI/CD pipeline. The security pipeline is designed to catch vulnerabilities before they reach production while minimizing friction for developers.

## Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Pull Request / Push                               │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                    ┌─────────────────┼─────────────────┐
                    │                 │                 │
                    ▼                 ▼                 ▼
          ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
          │  PR Validation  │ │    Security     │ │   Build/Push    │
          │   (existing)    │ │   (blocking)    │ │   (on main)     │
          └─────────────────┘ └─────────────────┘ └─────────────────┘
                    │                 │                 │
                    │                 ▼                 │
                    │    ┌───────────────────────┐     │
                    │    │   Security Checks:    │     │
                    │    │ • Semgrep SAST        │     │
                    │    │ • Gitleaks Secrets    │     │
                    │    │ • npm audit           │     │
                    │    │ • Trivy Container     │     │
                    │    │ • Checkov IaC         │     │
                    │    │ • CodeQL              │     │
                    │    │ • License Compliance  │     │
                    │    └───────────────────────┘     │
                    │                 │                 │
                    └─────────────────┼─────────────────┘
                                      ▼
                         ┌─────────────────────┐
                         │  Branch Protection  │
                         │  (all must pass)    │
                         └─────────────────────┘
```

## Security Checks

### 1. SAST (Static Application Security Testing)

**Tool:** Semgrep + CodeQL

**What it detects:**

- SQL Injection (Prisma `$queryRawUnsafe`, string interpolation)
- Server-Side Request Forgery (SSRF)
- Cross-Site Scripting (XSS)
- Insecure Direct Object Reference (IDOR)
- Missing authentication guards
- Hardcoded secrets
- Weak cryptography
- Mass assignment vulnerabilities

**Custom Rules Location:** `.semgrep/`

- `grc-security.yml` - GRC-specific patterns
- `auth-rules.yml` - Authentication/authorization rules
- `injection-rules.yml` - Injection attack patterns

**Severity Levels:**
| Level | Action |
|-------|--------|
| ERROR | Blocks PR merge |
| WARNING | Shown in PR, doesn't block |
| INFO | Informational only |

### 2. Secret Detection

**Tools:** Gitleaks, TruffleHog

**What it detects:**

- AWS credentials (access keys, secret keys)
- API keys and tokens
- Private keys (RSA, SSH, EC)
- Database connection strings
- OAuth client secrets
- JWT secrets
- Generic passwords

**Configuration:** `.gitleaks.toml`

**Excluding False Positives:**

```python
# In code, add a comment to exclude a specific line:
api_key = get_from_env("API_KEY")  # gitleaks:allow

# Or add to .gitleaks.toml allowlist
```

### 3. Dependency Scanning

**Tool:** npm audit

**Blocking Levels:** HIGH, CRITICAL

**What it checks:**

- Known vulnerabilities in npm packages
- Outdated packages with security patches
- License compliance

### 4. Container Scanning

**Tool:** Trivy

**What it detects:**

- OS package vulnerabilities
- Application dependency vulnerabilities
- Misconfigurations in Dockerfiles
- Secrets in container images

**Blocking:** CRITICAL and HIGH severity findings

### 5. Infrastructure as Code (IaC) Scanning

**Tool:** Checkov

**What it scans:**

- Terraform configurations
- Docker Compose files
- Kubernetes manifests (if added)

**Common Findings:**

- Missing encryption at rest
- Overly permissive security groups
- Unencrypted S3 buckets
- Missing logging/monitoring

### 6. License Compliance

**Allowed Licenses:**

- MIT
- Apache-2.0
- BSD-2-Clause / BSD-3-Clause
- ISC
- CC0-1.0
- Unlicense
- 0BSD

**Restricted Licenses (will warn):**

- GPL (copyleft concerns)
- AGPL (network copyleft)
- Unknown

## Pre-commit Hooks

Before code reaches CI, local pre-commit hooks provide early feedback:

```bash
# Runs automatically on git commit
.husky/pre-commit

# Checks performed:
# 1. lint-staged (formatting, linting)
# 2. Gitleaks (if installed locally)
# 3. Pattern-based secret detection
# 4. .env file commit prevention
# 5. console.log detection in backend
# 6. Debug flag detection
# 7. Large file detection (>5MB)
```

**Installing Gitleaks locally:**

```bash
# macOS
brew install gitleaks

# Linux
wget https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_x64.tar.gz
tar -xzf gitleaks_linux_x64.tar.gz
sudo mv gitleaks /usr/local/bin/

# Verify
gitleaks version
```

## Dependabot

Automated dependency updates are configured in `.github/dependabot.yml`:

| Ecosystem      | Schedule | Grouping                             |
| -------------- | -------- | ------------------------------------ |
| npm (root)     | Daily    | Security separate, dev/patch grouped |
| npm (frontend) | Weekly   | UI components grouped                |
| GitHub Actions | Weekly   | All grouped                          |
| Docker         | Weekly   | Per service                          |
| Terraform      | Weekly   | -                                    |

**Auto-merge:** Enabled for patch updates via workflow (requires setup)

## CODEOWNERS

Security-sensitive files require additional review. See `.github/CODEOWNERS`:

| Path Pattern           | Required Reviewers                   |
| ---------------------- | ------------------------------------ |
| `services/*/src/auth/` | @security-team                       |
| `terraform/`           | @infrastructure-team, @security-team |
| `.semgrep/`            | @security-team                       |
| `**/schema.prisma`     | @security-team                       |

## Branch Protection Setup

Configure these settings in GitHub repository settings:

### Required Status Checks

Navigate to: **Settings → Branches → Branch protection rules → Edit**

Add these required status checks:

- `Security / SAST Scan`
- `Security / Secret Scan`
- `Security / Dependency Scan`
- `Security / Container Scan / controls`
- `Security / Container Scan / audit`
- `Security / Container Scan / tprm`
- `Security / Container Scan / trust`
- `Security / Container Scan / policies`
- `Security / Container Scan / frameworks`
- `Security / IaC Security Scan`
- `Security / Security Summary`

### Recommended Settings

```yaml
Branch protection rule for: main

✅ Require a pull request before merging
  ✅ Require approvals: 1
  ✅ Dismiss stale pull request approvals when new commits are pushed
  ✅ Require review from Code Owners

✅ Require status checks to pass before merging
  ✅ Require branches to be up to date before merging
  Status checks: (add all from above)

✅ Require conversation resolution before merging

✅ Do not allow bypassing the above settings
```

## Handling Security Findings

### In PRs

1. **Review the Security tab** - GitHub Security tab shows all SARIF-uploaded findings
2. **Check workflow summary** - Each security job provides a summary in the PR
3. **Fix or document** - Either fix the issue or document why it's a false positive

### False Positive Management

**Semgrep:**

```typescript
// nosemgrep: rule-id
const legacyCode = 'this is intentional';
```

**Gitleaks:**

```python
api_key = "known-test-key"  # gitleaks:allow
```

**Trivy:**
Add to `.trivyignore`:

```
CVE-2023-XXXXX
```

**Checkov:**

```hcl
# checkov:skip=CKV_AWS_144: Reason for skipping
resource "aws_s3_bucket" "example" {
  ...
}
```

## Security Scanning Schedule

| Scan Type    | PR Trigger | Push Trigger | Scheduled              |
| ------------ | ---------- | ------------ | ---------------------- |
| Semgrep SAST | ✅         | ✅           | Daily 2 AM UTC         |
| Gitleaks     | ✅         | ✅           | Daily 2 AM UTC         |
| npm audit    | ✅         | ✅           | Daily 2 AM UTC         |
| Trivy        | ✅         | ✅           | Daily 2 AM UTC         |
| Checkov      | ✅         | ✅           | Daily 2 AM UTC         |
| CodeQL       | ✅         | ✅           | Daily 2 AM UTC         |
| Dependabot   | -          | -            | See Dependabot section |

## Troubleshooting

### "Security scan is blocking my PR but I think it's wrong"

1. Check the specific finding in the workflow logs
2. Determine if it's a true positive or false positive
3. If false positive:
   - Add inline suppression comment
   - Update `.gitleaks.toml` or `.trivyignore`
   - Request security team review for bulk suppressions

### "Security workflow is failing but I don't see any findings"

1. Check if the workflow can build the Docker image (container scan)
2. Check if Terraform is valid (IaC scan)
3. Review the full workflow logs for setup errors

### "Gitleaks is detecting secrets in test files"

Add the path to `.gitleaks.toml` allowlist:

```toml
[allowlist]
  paths = [
    '''tests/fixtures/.*''',
    '''__mocks__/.*''',
  ]
```

### "npm audit is failing but I can't update the package"

1. Check if there's a patch version available
2. If the vulnerability is in a dev dependency and not exploitable in production, document it
3. Consider finding an alternative package
4. As a last resort, use `npm audit fix --force` (may cause breaking changes)

## Metrics and Reporting

Security scan results are uploaded to GitHub Security tab (SARIF format) for:

- Semgrep findings
- Trivy findings
- Checkov findings
- CodeQL findings

Access via: **Repository → Security → Code scanning alerts**

## Contact

For questions about security scanning or false positive reviews:

- Create an issue with the `security` label
- Tag @grcengineering/security-team in PR comments
