import { Injectable, Logger } from '@nestjs/common';
import {
  SecurityFinding,
  SSLInfo,
  SecurityHeaders,
  DNSSecurityInfo,
  WebPresenceInfo,
  ComplianceIndicators,
  CategoryScores,
  SubdomainScanResult,
  scoreToRiskLevel,
} from '../dto/security-scan.dto';

@Injectable()
export class RiskAnalyzer {
  private readonly logger = new Logger(RiskAnalyzer.name);

  /**
   * Analyze collected data and generate risk scores and findings
   */
  analyze(data: {
    ssl: SSLInfo;
    securityHeaders: SecurityHeaders;
    missingHeaders: string[];
    dns: DNSSecurityInfo;
    webPresence: WebPresenceInfo;
    compliance: ComplianceIndicators;
    subdomains?: SubdomainScanResult;
  }): {
    categoryScores: CategoryScores;
    overallScore: number;
    findings: SecurityFinding[];
    keyRisks: string[];
    recommendations: string[];
    summary: string;
  } {
    const findings: SecurityFinding[] = [];

    // Analyze each category
    const securityScore = this.analyzeSecurityPosture(data, findings);
    const breachScore = this.analyzeBreachHistory(data, findings);
    const reputationScore = this.analyzeReputation(data, findings);
    const complianceScore = this.analyzeCompliance(data, findings);
    
    // Analyze subdomains (affects security score)
    this.analyzeSubdomains(data.subdomains, findings);

    const categoryScores: CategoryScores = {
      security: securityScore,
      breach: breachScore,
      reputation: reputationScore,
      compliance: complianceScore,
    };

    // Calculate overall score (weighted average)
    const overallScore = Math.round(
      (securityScore * 30 + breachScore * 30 + reputationScore * 20 + complianceScore * 20) / 100
    );

    // Generate key risks and recommendations
    const keyRisks = this.extractKeyRisks(findings);
    const recommendations = this.generateRecommendations(findings);
    const summary = this.generateSummary(categoryScores, overallScore, findings);

    return {
      categoryScores,
      overallScore,
      findings,
      keyRisks,
      recommendations,
      summary,
    };
  }

  private analyzeSecurityPosture(
    data: { ssl: SSLInfo; securityHeaders: SecurityHeaders; missingHeaders: string[]; dns: DNSSecurityInfo },
    findings: SecurityFinding[]
  ): number {
    let score = 100;

    // SSL/TLS checks
    if (!data.ssl.enabled) {
      score -= 30;
      findings.push({
        id: 'SEC-001',
        category: 'Security',
        level: 'Critical',
        title: 'No SSL/TLS Encryption',
        description: 'The target website does not use SSL/TLS encryption',
        impact: 'Data transmitted between users and the server is not encrypted, exposing sensitive information',
        remediation: 'Implement SSL/TLS certificates (e.g., Let\'s Encrypt) and redirect all HTTP traffic to HTTPS',
      });
    } else {
      // Check SSL grade
      if (data.ssl.grade === 'F') {
        score -= 25;
        findings.push({
          id: 'SEC-002',
          category: 'Security',
          level: 'Critical',
          title: 'Invalid or Expired SSL Certificate',
          description: `SSL certificate has issues (Grade: ${data.ssl.grade})`,
          impact: 'Users will see security warnings and may not be able to access the site',
          remediation: 'Renew or replace SSL certificate immediately',
        });
      } else if (data.ssl.grade === 'C') {
        score -= 10;
        findings.push({
          id: 'SEC-003',
          category: 'Security',
          level: 'Medium',
          title: 'SSL Certificate Expiring Soon',
          description: `SSL certificate expires in ${data.ssl.daysUntilExpiry} days`,
          impact: 'Risk of service disruption if certificate is not renewed in time',
          remediation: 'Renew SSL certificate and implement automated renewal process',
        });
      }

      // Check HTTP to HTTPS redirect
      if (!data.ssl.httpRedirectsToHttps) {
        score -= 5;
        findings.push({
          id: 'SEC-004',
          category: 'Security',
          level: 'Medium',
          title: 'HTTP Traffic Not Redirected to HTTPS',
          description: 'HTTP requests are not automatically redirected to HTTPS',
          impact: 'Users accessing via HTTP will have unencrypted connections',
          remediation: 'Configure web server to redirect all HTTP traffic to HTTPS',
        });
      }
    }

    // Security headers checks
    const criticalHeaders = ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options'];
    const missingCritical = data.missingHeaders.filter((h) => criticalHeaders.includes(h));

    if (missingCritical.length > 0) {
      score -= missingCritical.length * 5;
      findings.push({
        id: 'SEC-005',
        category: 'Security',
        level: 'Medium',
        title: 'Missing Security Headers',
        description: `The following security headers are missing: ${missingCritical.join(', ')}`,
        impact: 'Increased vulnerability to clickjacking, XSS, and other web attacks',
        remediation: 'Configure web server to include all recommended security headers',
      });
    }

    // CSP quality check
    if (data.securityHeaders.contentSecurityPolicy) {
      const csp = data.securityHeaders.contentSecurityPolicy.toLowerCase();
      if (csp.includes('unsafe-inline')) {
        score -= 5;
        findings.push({
          id: 'SEC-006',
          category: 'Security',
          level: 'High',
          title: 'CSP Allows unsafe-inline',
          description: 'Content-Security-Policy allows \'unsafe-inline\', weakening XSS protection',
          impact: 'Inline scripts and styles can execute, allowing many XSS attack vectors',
          remediation: 'Remove \'unsafe-inline\' from CSP. Use nonces or hashes for inline scripts',
        });
      }
    }

    // DNS security checks
    if (!data.dns.hasSPF) {
      score -= 5;
      findings.push({
        id: 'SEC-007',
        category: 'Security',
        level: 'Medium',
        title: 'Missing SPF Record',
        description: 'Domain does not have an SPF (Sender Policy Framework) record configured',
        impact: 'Increased risk of email spoofing and phishing attacks using the domain',
        remediation: 'Add SPF record to DNS to specify authorized email senders',
      });
    }

    if (!data.dns.hasDMARC) {
      score -= 5;
      findings.push({
        id: 'SEC-008',
        category: 'Security',
        level: 'Medium',
        title: 'Missing DMARC Record',
        description: 'Domain does not have a DMARC record configured',
        impact: 'Cannot enforce email authentication policy. Domain is vulnerable to email spoofing',
        remediation: 'Add DMARC record to _dmarc subdomain',
      });
    }

    return Math.max(0, Math.min(100, score));
  }

  private analyzeBreachHistory(
    data: { compliance: ComplianceIndicators },
    findings: SecurityFinding[]
  ): number {
    // Without external breach database integration, we provide a baseline score
    // In a full implementation, this would integrate with HaveIBeenPwned API or similar
    const score = 80; // Baseline - no breach data available

    findings.push({
      id: 'BREACH-001',
      category: 'Breach',
      level: 'Info',
      title: 'Breach History Check Limited',
      description: 'Automated breach database lookup requires API integration',
      impact: 'Cannot automatically verify breach history',
      remediation: 'Manually check HaveIBeenPwned.com or request breach attestation from vendor',
    });

    return score;
  }

  private analyzeReputation(
    data: { webPresence: WebPresenceInfo },
    findings: SecurityFinding[]
  ): number {
    let score = 100;

    // Website accessibility
    if (!data.webPresence.accessible) {
      score -= 20;
      findings.push({
        id: 'REP-001',
        category: 'Reputation',
        level: data.webPresence.statusCode && data.webPresence.statusCode >= 500 ? 'High' : 'Medium',
        title: 'Website Accessibility Issues',
        description: `Website returned HTTP status code ${data.webPresence.statusCode || 'unknown'}`,
        impact: 'Potential service availability issues or website downtime',
        remediation: 'Investigate website hosting and infrastructure issues',
      });
    }

    // Contact information
    if (!data.webPresence.hasContactInfo) {
      score -= 5;
      findings.push({
        id: 'REP-002',
        category: 'Reputation',
        level: 'Low',
        title: 'No Contact Information Found',
        description: 'No contact email address found on website',
        impact: 'Difficulty in reaching out for security issues or business inquiries',
        remediation: 'Ensure contact information is clearly displayed on website',
      });
    }

    return Math.max(0, Math.min(100, score));
  }

  private analyzeCompliance(
    data: { webPresence: WebPresenceInfo; compliance: ComplianceIndicators },
    findings: SecurityFinding[]
  ): number {
    let score = 0; // Start at zero - company must earn compliance points

    // Privacy Policy (required - 10 points)
    if (data.webPresence.hasPrivacyPolicy) {
      score += 10;
    } else {
      findings.push({
        id: 'COMP-001',
        category: 'Compliance',
        level: 'Critical',
        title: 'No Privacy Policy Found',
        description: 'Could not locate a privacy policy on the website',
        impact: 'Critical non-compliance with GDPR, CCPA, and other privacy regulations',
        remediation: 'Publish comprehensive privacy policy immediately',
      });
    }

    // SOC 2 (critical - 25 points)
    if (data.compliance.hasSOC2) {
      score += 20;
      if (data.compliance.soc2Type === 'Type II') {
        score += 5;
      }
      findings.push({
        id: 'COMP-002',
        category: 'Compliance',
        level: 'Info',
        title: `SOC 2 ${data.compliance.soc2Type || ''} Report Available`,
        description: 'Company provides SOC 2 audit reports',
        impact: 'Independent third-party validation of security controls',
        remediation: 'Continue annual SOC 2 audits and keep reports current',
      });
    } else {
      findings.push({
        id: 'COMP-003',
        category: 'Compliance',
        level: 'High',
        title: 'No SOC 2 Report Found',
        description: 'No SOC 2 Type I or Type II audit report available',
        impact: 'Cannot verify security controls through independent third-party audit',
        remediation: 'Complete SOC 2 Type II audit - essential for B2B trust',
      });
    }

    // ISO 27001 (15 points)
    if (data.compliance.hasISO27001) {
      score += 15;
      findings.push({
        id: 'COMP-004',
        category: 'Compliance',
        level: 'Info',
        title: 'ISO 27001 Certified',
        description: 'Company holds ISO 27001 certification',
        impact: 'International standard for information security management',
        remediation: 'Maintain certification through annual surveillance audits',
      });
    }

    // Trust Portal (10 points)
    if (data.compliance.hasTrustPortal) {
      score += 10;
      findings.push({
        id: 'COMP-005',
        category: 'Compliance',
        level: 'Info',
        title: 'Trust Portal Found',
        description: `Dedicated security trust portal detected${data.compliance.trustPortalProvider ? ` (Provider: ${data.compliance.trustPortalProvider})` : ''}`,
        impact: 'Demonstrates commitment to security transparency',
        remediation: 'Continue maintaining transparency through trust portal updates',
      });
    } else {
      findings.push({
        id: 'COMP-006',
        category: 'Compliance',
        level: 'Medium',
        title: 'No Trust Portal Detected',
        description: 'No dedicated security trust portal found',
        impact: 'Limited visibility into security posture and compliance status',
        remediation: 'Consider establishing a public trust portal using Vanta, Drata, or SecureFrame',
      });
    }

    // Bug Bounty (5 points)
    if (data.compliance.hasBugBounty) {
      score += 5;
      findings.push({
        id: 'COMP-007',
        category: 'Compliance',
        level: 'Info',
        title: 'Bug Bounty Program Active',
        description: 'Company operates a bug bounty or responsible disclosure program',
        impact: 'Proactive security posture with crowdsourced vulnerability discovery',
        remediation: 'Continue program and maintain clear disclosure guidelines',
      });
    }

    // Additional certifications
    const extraCerts = data.compliance.certifications.filter(
      (c) => !['SOC 2', 'SOC 2 Type I', 'SOC 2 Type II', 'ISO 27001'].includes(c)
    );
    score += Math.min(5, extraCerts.length);

    return Math.max(0, Math.min(100, score));
  }

  private extractKeyRisks(findings: SecurityFinding[]): string[] {
    return findings
      .filter((f) => f.level === 'Critical' || f.level === 'High')
      .map((f) => f.title)
      .slice(0, 5);
  }

  private generateRecommendations(findings: SecurityFinding[]): string[] {
    return findings
      .filter((f) => f.level === 'Critical' || f.level === 'High' || f.level === 'Medium')
      .map((f) => f.remediation)
      .slice(0, 5);
  }

  private generateSummary(
    scores: CategoryScores,
    overallScore: number,
    findings: SecurityFinding[]
  ): string {
    const riskLevel = scoreToRiskLevel(overallScore);
    const criticalCount = findings.filter((f) => f.level === 'Critical').length;
    const highCount = findings.filter((f) => f.level === 'High').length;

    let summary = `Overall risk level: ${riskLevel} (Score: ${overallScore}/100). `;

    if (criticalCount > 0) {
      summary += `Found ${criticalCount} critical issue(s) requiring immediate attention. `;
    }

    if (highCount > 0) {
      summary += `Found ${highCount} high-priority issue(s). `;
    }

    summary += `Security posture score: ${scores.security}/100. `;
    summary += `Compliance score: ${scores.compliance}/100.`;

    return summary;
  }

  /**
   * Analyze discovered subdomains for security issues
   */
  private analyzeSubdomains(
    subdomains: SubdomainScanResult | undefined,
    findings: SecurityFinding[]
  ): void {
    if (!subdomains || subdomains.discovered.length === 0) {
      return;
    }

    // Check for dev/staging/test subdomains that are publicly accessible
    const sensitiveSubdomains = ['dev', 'staging', 'test', 'beta', 'demo', 'admin', 'internal'];
    const exposedSensitive = subdomains.discovered.filter(
      (s) => sensitiveSubdomains.includes(s.subdomain) && s.accessible
    );

    if (exposedSensitive.length > 0) {
      findings.push({
        id: 'SUB-001',
        category: 'Security',
        level: 'High',
        title: 'Sensitive Subdomains Publicly Accessible',
        description: `The following development/staging subdomains are publicly accessible: ${exposedSensitive.map(s => s.fullDomain).join(', ')}`,
        impact: 'Development and staging environments may contain test data, debug features, or weaker security controls',
        remediation: 'Restrict access to development/staging environments via VPN, IP whitelist, or authentication',
      });
    }

    // Check for subdomains without SSL
    const noSSLSubdomains = subdomains.discovered.filter(
      (s) => s.accessible && s.hasSSL === false
    );

    if (noSSLSubdomains.length > 0) {
      findings.push({
        id: 'SUB-002',
        category: 'Security',
        level: 'Medium',
        title: 'Subdomains Without SSL/TLS',
        description: `The following subdomains do not use HTTPS: ${noSSLSubdomains.map(s => s.fullDomain).join(', ')}`,
        impact: 'Traffic to these subdomains is unencrypted and may expose sensitive data',
        remediation: 'Implement SSL certificates for all publicly accessible subdomains',
      });
    }

    // Informational finding about discovered subdomains
    if (subdomains.discovered.length > 0) {
      findings.push({
        id: 'SUB-003',
        category: 'Reputation',
        level: 'Info',
        title: `${subdomains.discovered.length} Subdomains Discovered`,
        description: `Spider discovered ${subdomains.discovered.length} active subdomains: ${subdomains.discovered.slice(0, 5).map(s => s.subdomain).join(', ')}${subdomains.discovered.length > 5 ? '...' : ''}`,
        impact: 'Large attack surface may increase security risk if not properly managed',
        remediation: 'Regularly audit subdomains and decommission unused services',
      });
    }

    // Wildcard DNS warning
    if (subdomains.hasWildcard) {
      findings.push({
        id: 'SUB-004',
        category: 'Security',
        level: 'Low',
        title: 'Wildcard DNS Configured',
        description: `Domain uses wildcard DNS (*.${subdomains.domain})`,
        impact: 'All subdomain requests resolve to the same IP, which may mask phishing attempts',
        remediation: 'Consider whether wildcard DNS is necessary for your use case',
      });
    }
  }
}
