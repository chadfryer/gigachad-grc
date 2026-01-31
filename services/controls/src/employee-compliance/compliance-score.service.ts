import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

export interface ComplianceIssue {
  type: 'background_check' | 'training' | 'attestation' | 'access_review' | 'device' | 'mfa';
  severity: 'critical' | 'high' | 'medium' | 'low';
  message: string;
  details?: Record<string, any>;
}

export interface ScoreBreakdown {
  backgroundCheck: number;      // 0-25 points
  training: number;             // 0-25 points
  attestation: number;          // 0-25 points
  accessReview: number;         // 0-25 points
  total: number;                // 0-100 points
  issues: ComplianceIssue[];
}

@Injectable()
export class ComplianceScoreService {
  private readonly logger = new Logger(ComplianceScoreService.name);

  constructor(private readonly prisma: PrismaService) {}

  /**
   * Calculate compliance score for a single employee
   */
  async calculateEmployeeScore(employeeId: string): Promise<ScoreBreakdown> {
    const employee = await this.prisma.correlatedEmployee.findUnique({
      where: { id: employeeId },
      include: {
        backgroundChecks: {
          orderBy: { completedAt: 'desc' },
          take: 1,
        },
        trainingRecords: {
          where: {
            OR: [
              { status: 'assigned' },
              { status: 'in_progress' },
              { status: 'overdue' },
              { status: 'completed' },
            ],
          },
        },
        attestations: true,
        accessRecords: {
          orderBy: { updatedAt: 'desc' },
          take: 1,
        },
        assetAssignments: true,
      },
    });

    if (!employee) {
      return {
        backgroundCheck: 0,
        training: 0,
        attestation: 0,
        accessReview: 0,
        total: 0,
        issues: [{ type: 'background_check', severity: 'critical', message: 'Employee not found' }],
      };
    }

    const issues: ComplianceIssue[] = [];

    // Background Check Score (0-25 points)
    const backgroundCheckScore = this.calculateBackgroundCheckScore(
      employee.backgroundChecks,
      issues,
    );

    // Training Score (0-25 points)
    const trainingScore = this.calculateTrainingScore(
      employee.trainingRecords,
      issues,
    );

    // Attestation Score (0-25 points)
    const attestationScore = this.calculateAttestationScore(
      employee.attestations,
      issues,
    );

    // Access Review Score (0-25 points)
    const accessReviewScore = this.calculateAccessReviewScore(
      employee.accessRecords,
      employee.assetAssignments,
      issues,
    );

    const total = backgroundCheckScore + trainingScore + attestationScore + accessReviewScore;

    return {
      backgroundCheck: backgroundCheckScore,
      training: trainingScore,
      attestation: attestationScore,
      accessReview: accessReviewScore,
      total,
      issues,
    };
  }

  /**
   * Calculate background check score component
   */
  private calculateBackgroundCheckScore(
    backgroundChecks: any[],
    issues: ComplianceIssue[],
  ): number {
    if (!backgroundChecks || backgroundChecks.length === 0) {
      issues.push({
        type: 'background_check',
        severity: 'high',
        message: 'No background check on file',
      });
      return 0;
    }

    const latestCheck = backgroundChecks[0];
    const now = new Date();

    // Check if expired
    if (latestCheck.expiresAt && new Date(latestCheck.expiresAt) < now) {
      issues.push({
        type: 'background_check',
        severity: 'high',
        message: 'Background check expired',
        details: { expiresAt: latestCheck.expiresAt },
      });
      return 5; // Partial credit for having had one
    }

    // Check status
    switch (latestCheck.status) {
      case 'clear':
        return 25; // Full points

      case 'pending':
      case 'in_progress':
        issues.push({
          type: 'background_check',
          severity: 'medium',
          message: 'Background check in progress',
          details: { status: latestCheck.status },
        });
        return 15; // Partial credit

      case 'flagged':
        issues.push({
          type: 'background_check',
          severity: 'critical',
          message: 'Background check flagged - review required',
          details: { status: latestCheck.status },
        });
        return 5;

      default:
        return 10;
    }
  }

  /**
   * Calculate training score component
   */
  private calculateTrainingScore(
    trainingRecords: any[],
    issues: ComplianceIssue[],
  ): number {
    if (!trainingRecords || trainingRecords.length === 0) {
      // No training records could mean no assigned training (which is fine)
      // or could mean missing LMS integration
      return 25; // Give benefit of doubt if no data
    }

    const _requiredTrainings = trainingRecords.filter(
      (t) => t.courseType === 'required' || t.isRequired,
    );
    const allTrainings = trainingRecords;

    // Count completed vs overdue
    const completed = allTrainings.filter((t) => t.status === 'completed').length;
    const overdue = allTrainings.filter((t) => t.status === 'overdue').length;
    const inProgress = allTrainings.filter(
      (t) => t.status === 'in_progress' || t.status === 'assigned',
    ).length;

    if (overdue > 0) {
      issues.push({
        type: 'training',
        severity: 'high',
        message: `${overdue} training(s) overdue`,
        details: { overdue, total: allTrainings.length },
      });
    }

    if (inProgress > 0) {
      issues.push({
        type: 'training',
        severity: 'low',
        message: `${inProgress} training(s) in progress`,
        details: { inProgress },
      });
    }

    // Calculate score based on completion rate
    const total = allTrainings.length;
    if (total === 0) return 25;

    const completionRate = completed / total;
    const overdueRate = overdue / total;

    // Penalize heavily for overdue trainings
    if (overdueRate > 0.5) return 5;
    if (overdueRate > 0.25) return 10;
    if (overdueRate > 0) return 15;

    // Reward completion
    if (completionRate >= 1) return 25;
    if (completionRate >= 0.75) return 20;
    if (completionRate >= 0.5) return 15;

    return 10;
  }

  /**
   * Calculate attestation score component
   */
  private calculateAttestationScore(
    attestations: any[],
    issues: ComplianceIssue[],
  ): number {
    if (!attestations || attestations.length === 0) {
      // No attestations could mean no policies to acknowledge
      return 25; // Give benefit of doubt
    }

    const pending = attestations.filter((a) => a.status === 'pending').length;
    const declined = attestations.filter((a) => a.status === 'declined').length;
    const expired = attestations.filter((a) => a.status === 'expired').length;
    const acknowledged = attestations.filter((a) => a.status === 'acknowledged').length;

    if (declined > 0) {
      issues.push({
        type: 'attestation',
        severity: 'critical',
        message: `${declined} policy attestation(s) declined`,
        details: { declined },
      });
    }

    if (expired > 0) {
      issues.push({
        type: 'attestation',
        severity: 'high',
        message: `${expired} policy attestation(s) expired`,
        details: { expired },
      });
    }

    if (pending > 0) {
      issues.push({
        type: 'attestation',
        severity: 'medium',
        message: `${pending} policy attestation(s) pending`,
        details: { pending },
      });
    }

    const total = attestations.length;
    if (total === 0) return 25;

    // Declined is worst
    if (declined > 0) return 0;

    // Expired is bad
    const expiredRate = expired / total;
    if (expiredRate > 0.5) return 5;
    if (expiredRate > 0) return 15;

    // Pending reduces score
    const acknowledgedRate = acknowledged / total;
    if (acknowledgedRate >= 1) return 25;
    if (acknowledgedRate >= 0.75) return 20;
    if (acknowledgedRate >= 0.5) return 15;

    return 10;
  }

  /**
   * Calculate access review score component
   */
  private calculateAccessReviewScore(
    accessRecords: any[],
    assetAssignments: any[],
    issues: ComplianceIssue[],
  ): number {
    let score = 25;

    // Check access reviews
    if (accessRecords && accessRecords.length > 0) {
      const latestAccess = accessRecords[0];

      if (latestAccess.reviewStatus === 'action_required') {
        issues.push({
          type: 'access_review',
          severity: 'high',
          message: 'Access review requires action',
        });
        score -= 10;
      }

      if (latestAccess.reviewStatus === 'pending') {
        issues.push({
          type: 'access_review',
          severity: 'medium',
          message: 'Access review pending',
        });
        score -= 5;
      }

      // Check MFA
      if (latestAccess.mfaEnabled === false) {
        issues.push({
          type: 'mfa',
          severity: 'high',
          message: 'MFA not enabled',
        });
        score -= 5;
      }
    }

    // Check device compliance
    if (assetAssignments && assetAssignments.length > 0) {
      const nonCompliantDevices = assetAssignments.filter(
        (a) => a.isCompliant === false,
      );

      if (nonCompliantDevices.length > 0) {
        issues.push({
          type: 'device',
          severity: 'medium',
          message: `${nonCompliantDevices.length} device(s) non-compliant`,
          details: {
            devices: nonCompliantDevices.map((d) => d.deviceName || d.serialNumber),
          },
        });
        score -= 5;
      }
    }

    return Math.max(0, score);
  }

  /**
   * Update compliance score for an employee
   */
  async updateEmployeeScore(employeeId: string): Promise<void> {
    const scoreBreakdown = await this.calculateEmployeeScore(employeeId);

    await this.prisma.correlatedEmployee.update({
      where: { id: employeeId },
      data: {
        complianceScore: scoreBreakdown.total,
        complianceIssues: scoreBreakdown.issues as any,
      },
    });
  }

  /**
   * Recalculate scores for all employees in an organization
   */
  async recalculateOrganizationScores(organizationId: string): Promise<number> {
    const batchSize = 500;
    let updated = 0;
    let cursor: string | null = null;

    while (true) {
      const employees = await this.prisma.correlatedEmployee.findMany({
        where: { organizationId },
        select: { id: true },
        orderBy: { id: 'asc' },
        take: batchSize,
        ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {}),
      });

      if (employees.length === 0) {
        break;
      }

      for (const employee of employees) {
        await this.updateEmployeeScore(employee.id);
        updated++;
      }

      // Prepare cursor for next batch
      cursor = employees[employees.length - 1].id;
      if (employees.length < batchSize) {
        break;
      }
    }

    this.logger.log(`Updated compliance scores for ${updated} employees`);
    return updated;
  }

  /**
   * Get organization-wide compliance metrics
   */
  async getOrganizationMetrics(organizationId: string): Promise<{
    totalEmployees: number;
    averageScore: number;
    scoreDistribution: { compliant: number; atRisk: number; nonCompliant: number };
    issueBreakdown: { 
      overdueTrainings: number; 
      missingBackgroundChecks: number; 
      pendingAttestations: number; 
      mfaNotEnabled: number; 
      nonCompliantDevices: number;
    };
    complianceRate: number;
  }> {
    const employees = await this.prisma.correlatedEmployee.findMany({
      where: {
        organizationId,
        employmentStatus: 'active',
      },
      select: {
        complianceScore: true,
        complianceIssues: true,
      },
    });

    const totalEmployees = employees.length;
    if (totalEmployees === 0) {
      return {
        totalEmployees: 0,
        averageScore: 0,
        scoreDistribution: { compliant: 0, atRisk: 0, nonCompliant: 0 },
        issueBreakdown: {
          overdueTrainings: 0,
          missingBackgroundChecks: 0,
          pendingAttestations: 0,
          mfaNotEnabled: 0,
          nonCompliantDevices: 0,
        },
        complianceRate: 0,
      };
    }

    // Calculate average score
    const scores = employees.map((e) => e.complianceScore || 0);
    const averageScore = Math.round(
      scores.reduce((sum, s) => sum + s, 0) / totalEmployees,
    );

    // Score distribution - grouped by compliance status
    const scoreDistribution = {
      compliant: scores.filter((s) => s >= 80).length,
      atRisk: scores.filter((s) => s >= 60 && s < 80).length,
      nonCompliant: scores.filter((s) => s < 60).length,
    };

    // Issue breakdown - count by issue type
    const issueTypeCounts: Record<string, number> = {
      training: 0,
      background_check: 0,
      attestation: 0,
      mfa: 0,
      device: 0,
    };
    
    for (const employee of employees) {
      const issues = (employee.complianceIssues as unknown as ComplianceIssue[]) || [];
      for (const issue of issues) {
        if (issueTypeCounts[issue.type] !== undefined) {
          issueTypeCounts[issue.type]++;
        }
      }
    }

    const issueBreakdown = {
      overdueTrainings: issueTypeCounts.training,
      missingBackgroundChecks: issueTypeCounts.background_check,
      pendingAttestations: issueTypeCounts.attestation,
      mfaNotEnabled: issueTypeCounts.mfa,
      nonCompliantDevices: issueTypeCounts.device,
    };

    // Compliance rate (employees with score >= 80)
    const compliantCount = scores.filter((s) => s >= 80).length;
    const complianceRate = Math.round((compliantCount / totalEmployees) * 100);

    return {
      totalEmployees,
      averageScore,
      scoreDistribution,
      issueBreakdown,
      complianceRate,
    };
  }
}

