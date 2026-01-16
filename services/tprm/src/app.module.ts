import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { VendorsModule } from './vendors/vendors.module';
import { AssessmentsModule } from './assessments/assessments.module';
import { ContractsModule } from './contracts/contracts.module';
import { VendorAIModule } from './ai/vendor-ai.module';
import { TprmConfigModule } from './config/tprm-config.module';
import { RiskAssessmentModule } from './risk-assessment/risk-assessment.module';
import { SecurityScannerModule } from './security-scanner/security-scanner.module';
import { PrismaService } from './common/prisma.service';
import { AuditService } from './common/audit.service';
import { StorageModule } from '@gigachad-grc/shared';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    StorageModule.forRoot(),
    // RiskAssessmentModule and SecurityScannerModule must be imported BEFORE VendorsModule
    // because their routes (/vendors/:id/risk-assessment/*, /vendors/:id/security-scan/*)
    // are more specific than VendorsModule's catch-all /:id route
    RiskAssessmentModule,
    SecurityScannerModule,
    VendorsModule,
    AssessmentsModule,
    ContractsModule,
    VendorAIModule,
    TprmConfigModule,
  ],
  providers: [PrismaService, AuditService],
  exports: [PrismaService, AuditService],
})
export class AppModule {}
