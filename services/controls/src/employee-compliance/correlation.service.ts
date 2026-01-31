import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

/**
 * Evidence types that the correlation engine processes for employee compliance
 */
const EMPLOYEE_EVIDENCE_TYPES = {
  // HRIS - creates/updates CorrelatedEmployee records
  EMPLOYEE_ROSTER: 'employee_roster',
  ORG_CHART: 'org_chart',
  EMPLOYMENT_STATUS: 'employment_status',
  ONBOARDING_STATUS: 'onboarding_status',
  OFFBOARDING_STATUS: 'offboarding_status',
  
  // Background Check
  BACKGROUND_CHECK_RESULTS: 'background_check_results',
  SCREENING_STATUS: 'screening_status',
  
  // LMS / Security Awareness
  TRAINING_ASSIGNMENTS: 'training_assignments',
  TRAINING_COMPLETIONS: 'training_completions',
  PHISHING_TEST_RESULTS: 'phishing_test_results',
  SECURITY_AWARENESS_SCORE: 'security_awareness_score',
  USER_TRAINING_STATUS: 'user_training_status',
  
  // MDM
  DEVICE_INVENTORY: 'device_inventory',
  DEVICE_ASSIGNMENTS: 'device_assignments',
  DEVICE_COMPLIANCE: 'device_compliance',
  
  // Identity
  USER_ACCESS_LIST: 'user_access_list',
  ACCESS_REVIEW_STATUS: 'access_review_status',
  APP_ASSIGNMENTS: 'app_assignments',
  MFA_STATUS: 'mfa_status',
};

interface EmployeeRosterRecord {
  email: string;
  firstName?: string;
  lastName?: string;
  department?: string;
  jobTitle?: string;
  managerEmail?: string;
  hireDate?: string;
  employmentStatus?: string;
  employmentType?: string;
  location?: string;
  employeeId?: string;
}

interface BackgroundCheckRecord {
  email: string;
  status: string;
  checkType?: string;
  initiatedAt?: string;
  completedAt?: string;
  expiresAt?: string;
  externalId?: string;
}

interface TrainingRecord {
  email: string;
  courseName: string;
  courseId?: string;
  status: string;
  assignedAt?: string;
  dueDate?: string;
  completedAt?: string;
  score?: number;
  isRequired?: boolean;
}

interface DeviceAssignment {
  email: string;
  deviceType: string;
  deviceName?: string;
  serialNumber?: string;
  model?: string;
  manufacturer?: string;
  osVersion?: string;
  isCompliant?: boolean;
  lastCheckIn?: string;
  assignedAt?: string;
  externalAssetId: string;
}

interface AccessRecord {
  email: string;
  systems: Array<{ name: string; accessLevel?: string; lastAccessed?: string }>;
  mfaEnabled?: boolean;
  lastReviewDate?: string;
  reviewStatus?: string;
}

interface SecurityScoreRecord {
  email: string;
  overallScore: number;
  riskLevel?: string;
  trainingScore?: number;
  phishingScore?: number;
  phishingTestsSent?: number;
  phishingTestsClicked?: number;
  phishingTestsReported?: number;
}

@Injectable()
export class CorrelationService {
  private readonly logger = new Logger(CorrelationService.name);

  constructor(private readonly prisma: PrismaService) {}

  /**
   * Check if an evidence type is employee-compliance related
   */
  isEmployeeComplianceEvidenceType(evidenceType: string): boolean {
    return Object.values(EMPLOYEE_EVIDENCE_TYPES).includes(evidenceType);
  }

  /**
   * Process evidence from an integration sync
   * Called after any integration syncs data
   */
  async processEvidenceSync(
    organizationId: string,
    integrationId: string,
    evidenceType: string,
    data: any[],
  ): Promise<{ processed: number; errors: number }> {
    if (!this.isEmployeeComplianceEvidenceType(evidenceType)) {
      return { processed: 0, errors: 0 };
    }

    this.logger.log(
      `Processing ${data.length} records for evidence type: ${evidenceType}`,
    );

    let processed = 0;
    let errors = 0;

    switch (evidenceType) {
      case EMPLOYEE_EVIDENCE_TYPES.EMPLOYEE_ROSTER: {
        const rosterResult = await this.handleEmployeeRoster(
          organizationId,
          integrationId,
          data as EmployeeRosterRecord[],
        );
        processed = rosterResult.processed;
        errors = rosterResult.errors;
        break;
      }

      case EMPLOYEE_EVIDENCE_TYPES.BACKGROUND_CHECK_RESULTS:
      case EMPLOYEE_EVIDENCE_TYPES.SCREENING_STATUS: {
        const bgResult = await this.handleBackgroundChecks(
          organizationId,
          integrationId,
          data as BackgroundCheckRecord[],
        );
        processed = bgResult.processed;
        errors = bgResult.errors;
        break;
      }

      case EMPLOYEE_EVIDENCE_TYPES.TRAINING_ASSIGNMENTS:
      case EMPLOYEE_EVIDENCE_TYPES.TRAINING_COMPLETIONS:
      case EMPLOYEE_EVIDENCE_TYPES.USER_TRAINING_STATUS: {
        const trainingResult = await this.handleTrainingRecords(
          organizationId,
          integrationId,
          data as TrainingRecord[],
        );
        processed = trainingResult.processed;
        errors = trainingResult.errors;
        break;
      }

      case EMPLOYEE_EVIDENCE_TYPES.DEVICE_INVENTORY:
      case EMPLOYEE_EVIDENCE_TYPES.DEVICE_ASSIGNMENTS: {
        const deviceResult = await this.handleDeviceAssignments(
          organizationId,
          integrationId,
          data as DeviceAssignment[],
        );
        processed = deviceResult.processed;
        errors = deviceResult.errors;
        break;
      }

      case EMPLOYEE_EVIDENCE_TYPES.USER_ACCESS_LIST:
      case EMPLOYEE_EVIDENCE_TYPES.APP_ASSIGNMENTS:
      case EMPLOYEE_EVIDENCE_TYPES.MFA_STATUS: {
        const accessResult = await this.handleAccessRecords(
          organizationId,
          integrationId,
          data as AccessRecord[],
        );
        processed = accessResult.processed;
        errors = accessResult.errors;
        break;
      }

      case EMPLOYEE_EVIDENCE_TYPES.SECURITY_AWARENESS_SCORE:
      case EMPLOYEE_EVIDENCE_TYPES.PHISHING_TEST_RESULTS: {
        const securityResult = await this.handleSecurityScores(
          organizationId,
          integrationId,
          data as SecurityScoreRecord[],
        );
        processed = securityResult.processed;
        errors = securityResult.errors;
        break;
      }

      default:
        this.logger.warn(`Unhandled evidence type: ${evidenceType}`);
    }

    return { processed, errors };
  }

  /**
   * Handle employee_roster evidence - creates/updates CorrelatedEmployee records
   * This is the source of truth for employees
   */
  private async handleEmployeeRoster(
    organizationId: string,
    integrationId: string,
    records: EmployeeRosterRecord[],
  ): Promise<{ processed: number; errors: number }> {
    let processed = 0;
    let errors = 0;

    for (const record of records) {
      try {
        if (!record.email) {
          this.logger.warn('Skipping record without email');
          errors++;
          continue;
        }

        const email = record.email.toLowerCase().trim();

        await this.prisma.correlatedEmployee.upsert({
          where: {
            organizationId_email: {
              organizationId,
              email,
            },
          },
          create: {
            organizationId,
            email,
            sourceIntegrationId: integrationId,
            externalId: record.employeeId,
            firstName: record.firstName,
            lastName: record.lastName,
            department: record.department,
            jobTitle: record.jobTitle,
            managerEmail: record.managerEmail?.toLowerCase(),
            hireDate: record.hireDate ? new Date(record.hireDate) : null,
            employmentStatus: record.employmentStatus || 'active',
            employmentType: record.employmentType,
            location: record.location,
            lastCorrelatedAt: new Date(),
          },
          update: {
            sourceIntegrationId: integrationId,
            externalId: record.employeeId,
            firstName: record.firstName,
            lastName: record.lastName,
            department: record.department,
            jobTitle: record.jobTitle,
            managerEmail: record.managerEmail?.toLowerCase(),
            hireDate: record.hireDate ? new Date(record.hireDate) : null,
            employmentStatus: record.employmentStatus || 'active',
            employmentType: record.employmentType,
            location: record.location,
            lastCorrelatedAt: new Date(),
          },
        });

        processed++;
      } catch (error) {
        this.logger.error(`Error processing employee roster record: ${error}`);
        errors++;
      }
    }

    return { processed, errors };
  }

  /**
   * Handle background_check_results evidence
   */
  private async handleBackgroundChecks(
    organizationId: string,
    integrationId: string,
    records: BackgroundCheckRecord[],
  ): Promise<{ processed: number; errors: number }> {
    let processed = 0;
    let errors = 0;

    for (const record of records) {
      try {
        if (!record.email) {
          errors++;
          continue;
        }

        const email = record.email.toLowerCase().trim();
        const employee = await this.findOrCreateEmployee(organizationId, email);

        if (!employee) {
          this.logger.warn(`Could not find/create employee for: ${email}`);
          errors++;
          continue;
        }

        const externalId = record.externalId || `${integrationId}_${email}_${record.checkType || 'general'}`;

        await this.prisma.employeeBackgroundCheck.upsert({
          where: {
            correlatedEmployeeId_integrationId_externalId: {
              correlatedEmployeeId: employee.id,
              integrationId,
              externalId,
            },
          },
          create: {
            correlatedEmployeeId: employee.id,
            integrationId,
            externalId,
            status: record.status,
            checkType: record.checkType,
            initiatedAt: record.initiatedAt ? new Date(record.initiatedAt) : null,
            completedAt: record.completedAt ? new Date(record.completedAt) : null,
            expiresAt: record.expiresAt ? new Date(record.expiresAt) : null,
            rawData: record as any,
          },
          update: {
            status: record.status,
            checkType: record.checkType,
            initiatedAt: record.initiatedAt ? new Date(record.initiatedAt) : null,
            completedAt: record.completedAt ? new Date(record.completedAt) : null,
            expiresAt: record.expiresAt ? new Date(record.expiresAt) : null,
            rawData: record as any,
          },
        });

        processed++;
      } catch (error) {
        this.logger.error(`Error processing background check record: ${error}`);
        errors++;
      }
    }

    return { processed, errors };
  }

  /**
   * Handle training evidence from LMS
   */
  private async handleTrainingRecords(
    organizationId: string,
    integrationId: string,
    records: TrainingRecord[],
  ): Promise<{ processed: number; errors: number }> {
    let processed = 0;
    let errors = 0;

    for (const record of records) {
      try {
        if (!record.email || !record.courseName) {
          errors++;
          continue;
        }

        const email = record.email.toLowerCase().trim();
        const employee = await this.findOrCreateEmployee(organizationId, email);

        if (!employee) {
          errors++;
          continue;
        }

        await this.prisma.employeeTrainingRecord.create({
          data: {
            correlatedEmployeeId: employee.id,
            integrationId,
            externalId: record.courseId,
            courseName: record.courseName,
            courseType: record.isRequired ? 'required' : 'optional',
            status: record.status,
            assignedAt: record.assignedAt ? new Date(record.assignedAt) : null,
            dueDate: record.dueDate ? new Date(record.dueDate) : null,
            completedAt: record.completedAt ? new Date(record.completedAt) : null,
            score: record.score,
            rawData: record as any,
          },
        });

        processed++;
      } catch (error) {
        this.logger.error(`Error processing training record: ${error}`);
        errors++;
      }
    }

    return { processed, errors };
  }

  /**
   * Handle device_inventory / device_assignments evidence from MDM
   */
  private async handleDeviceAssignments(
    organizationId: string,
    integrationId: string,
    records: DeviceAssignment[],
  ): Promise<{ processed: number; errors: number }> {
    let processed = 0;
    let errors = 0;

    for (const record of records) {
      try {
        if (!record.email || !record.externalAssetId) {
          errors++;
          continue;
        }

        const email = record.email.toLowerCase().trim();
        const employee = await this.findOrCreateEmployee(organizationId, email);

        if (!employee) {
          errors++;
          continue;
        }

        // Try to find matching Asset record by serial number
        let assetId: string | null = null;
        if (record.serialNumber) {
          const asset = await this.prisma.asset.findFirst({
            where: {
              organizationId,
              OR: [
                { externalId: record.externalAssetId },
                {
                  metadata: {
                    path: ['serialNumber'],
                    equals: record.serialNumber,
                  },
                },
              ],
            },
          });
          assetId = asset?.id || null;
        }

        await this.prisma.employeeAssetAssignment.upsert({
          where: {
            correlatedEmployeeId_integrationId_externalAssetId: {
              correlatedEmployeeId: employee.id,
              integrationId,
              externalAssetId: record.externalAssetId,
            },
          },
          create: {
            correlatedEmployeeId: employee.id,
            integrationId,
            assetId,
            externalAssetId: record.externalAssetId,
            deviceType: record.deviceType,
            deviceName: record.deviceName,
            serialNumber: record.serialNumber,
            model: record.model,
            manufacturer: record.manufacturer,
            osVersion: record.osVersion,
            isCompliant: record.isCompliant,
            lastCheckIn: record.lastCheckIn ? new Date(record.lastCheckIn) : null,
            assignedAt: record.assignedAt ? new Date(record.assignedAt) : null,
            rawData: record as any,
          },
          update: {
            assetId,
            deviceType: record.deviceType,
            deviceName: record.deviceName,
            serialNumber: record.serialNumber,
            model: record.model,
            manufacturer: record.manufacturer,
            osVersion: record.osVersion,
            isCompliant: record.isCompliant,
            lastCheckIn: record.lastCheckIn ? new Date(record.lastCheckIn) : null,
            rawData: record as any,
          },
        });

        processed++;
      } catch (error) {
        this.logger.error(`Error processing device assignment: ${error}`);
        errors++;
      }
    }

    return { processed, errors };
  }

  /**
   * Handle user_access_list / app_assignments evidence from identity providers
   */
  private async handleAccessRecords(
    organizationId: string,
    integrationId: string,
    records: AccessRecord[],
  ): Promise<{ processed: number; errors: number }> {
    let processed = 0;
    let errors = 0;

    for (const record of records) {
      try {
        if (!record.email) {
          errors++;
          continue;
        }

        const email = record.email.toLowerCase().trim();
        const employee = await this.findOrCreateEmployee(organizationId, email);

        if (!employee) {
          errors++;
          continue;
        }

        // Check if there's an existing access record for this integration
        const existing = await this.prisma.employeeAccessRecord.findFirst({
          where: {
            correlatedEmployeeId: employee.id,
            integrationId,
          },
        });

        if (existing) {
          await this.prisma.employeeAccessRecord.update({
            where: { id: existing.id },
            data: {
              systemsAccess: record.systems as any,
              mfaEnabled: record.mfaEnabled,
              lastReviewDate: record.lastReviewDate ? new Date(record.lastReviewDate) : null,
              reviewStatus: record.reviewStatus,
              rawData: record as any,
            },
          });
        } else {
          await this.prisma.employeeAccessRecord.create({
            data: {
              correlatedEmployeeId: employee.id,
              integrationId,
              systemsAccess: record.systems as any,
              mfaEnabled: record.mfaEnabled,
              lastReviewDate: record.lastReviewDate ? new Date(record.lastReviewDate) : null,
              reviewStatus: record.reviewStatus,
              rawData: record as any,
            },
          });
        }

        processed++;
      } catch (error) {
        this.logger.error(`Error processing access record: ${error}`);
        errors++;
      }
    }

    return { processed, errors };
  }

  /**
   * Handle security_awareness_score / phishing_test_results evidence
   */
  private async handleSecurityScores(
    organizationId: string,
    integrationId: string,
    records: SecurityScoreRecord[],
  ): Promise<{ processed: number; errors: number }> {
    let processed = 0;
    let errors = 0;

    for (const record of records) {
      try {
        if (!record.email) {
          errors++;
          continue;
        }

        const email = record.email.toLowerCase().trim();
        const employee = await this.findOrCreateEmployee(organizationId, email);

        if (!employee) {
          errors++;
          continue;
        }

        await this.prisma.employeeSecurityScore.create({
          data: {
            correlatedEmployeeId: employee.id,
            integrationId,
            overallScore: record.overallScore,
            riskLevel: record.riskLevel,
            trainingScore: record.trainingScore,
            phishingScore: record.phishingScore,
            phishingTestsSent: record.phishingTestsSent,
            phishingTestsClicked: record.phishingTestsClicked,
            phishingTestsReported: record.phishingTestsReported,
            lastUpdated: new Date(),
            rawData: record as any,
          },
        });

        processed++;
      } catch (error) {
        this.logger.error(`Error processing security score: ${error}`);
        errors++;
      }
    }

    return { processed, errors };
  }

  /**
   * Find an existing employee or create a placeholder
   */
  private async findOrCreateEmployee(
    organizationId: string,
    email: string,
  ): Promise<{ id: string } | null> {
    try {
      const existing = await this.prisma.correlatedEmployee.findUnique({
        where: {
          organizationId_email: {
            organizationId,
            email,
          },
        },
        select: { id: true },
      });

      if (existing) {
        return existing;
      }

      // Create a placeholder employee record
      // Will be enriched when HRIS sync happens
      const created = await this.prisma.correlatedEmployee.create({
        data: {
          organizationId,
          email,
          lastCorrelatedAt: new Date(),
        },
        select: { id: true },
      });

      return created;
    } catch (error) {
      this.logger.error(`Error finding/creating employee: ${error}`);
      return null;
    }
  }

  /**
   * Get all employee emails from an organization
   */
  async getOrganizationEmployeeEmails(organizationId: string): Promise<string[]> {
    const employees = await this.prisma.correlatedEmployee.findMany({
      where: { organizationId },
      select: { email: true },
    });
    return employees.map((e) => e.email);
  }
}




