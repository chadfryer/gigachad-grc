import {
  Controller,
  Post,
  Get,
  Body,
  Param,
  HttpCode,
  HttpStatus,
  UseGuards,
} from '@nestjs/common';
import {
  RiskWorkflowService,
  CreateRiskIntakeDto,
  ValidateRiskDto,
  AssignRiskAssessorDto,
  SubmitAssessmentDto,
  GrcReviewDto,
  SubmitTreatmentDecisionDto,
  SetExecutiveApproverDto,
  ExecutiveDecisionDto,
  MitigationUpdateDto,
} from './risk-workflow.service';
import { DevAuthGuard, User } from '../auth/dev-auth.guard';
import type { UserContext } from '@gigachad-grc/shared';
import { PermissionGuard } from '../auth/permission.guard';
import { RequirePermission } from '../auth/decorators/require-permission.decorator';
import { Resource, Action } from '../permissions/dto/permission.dto';

@Controller('api/risks/workflow')
@UseGuards(DevAuthGuard, PermissionGuard)
export class RiskWorkflowController {
  constructor(private readonly workflowService: RiskWorkflowService) {}

  // ===========================================
  // Risk Intake
  // ===========================================

  /**
   * Submit a new risk intake
   * POST /api/risks/workflow/intake
   */
  @Post('intake')
  @HttpCode(HttpStatus.CREATED)
  @RequirePermission(Resource.RISK, Action.CREATE)
  async submitRiskIntake(@Body() dto: CreateRiskIntakeDto, @User() user: UserContext) {
    return this.workflowService.submitRiskIntake(user.organizationId, dto, user.userId, user.email);
  }

  /**
   * Validate risk (GRC SME approves/declines)
   * POST /api/risks/workflow/:id/validate
   */
  @Post(':id/validate')
  @HttpCode(HttpStatus.OK)
  @RequirePermission(Resource.RISK, Action.UPDATE)
  async validateRisk(
    @Param('id') id: string,
    @Body() dto: ValidateRiskDto,
    @User() user: UserContext
  ) {
    return this.workflowService.validateRisk(id, user.organizationId, dto, user.userId, user.email);
  }

  /**
   * Assign risk assessor (moves to analysis)
   * POST /api/risks/workflow/:id/assign-assessor
   */
  @Post(':id/assign-assessor')
  @HttpCode(HttpStatus.OK)
  @RequirePermission(Resource.RISK, Action.UPDATE)
  async assignRiskAssessor(
    @Param('id') id: string,
    @Body() dto: AssignRiskAssessorDto,
    @User() user: UserContext
  ) {
    return this.workflowService.assignRiskAssessor(
      id,
      user.organizationId,
      dto,
      user.userId,
      user.email
    );
  }

  // ===========================================
  // Risk Assessment
  // ===========================================

  /**
   * Submit risk assessment (Risk Assessor)
   * POST /api/risks/workflow/:id/assessment/submit
   */
  @Post(':id/assessment/submit')
  @HttpCode(HttpStatus.OK)
  @RequirePermission(Resource.RISK, Action.UPDATE)
  async submitAssessment(
    @Param('id') id: string,
    @Body() dto: SubmitAssessmentDto,
    @User() user: UserContext
  ) {
    return this.workflowService.submitAssessment(
      id,
      user.organizationId,
      dto,
      user.userId,
      user.email
    );
  }

  /**
   * Review assessment (GRC SME approves/declines)
   * POST /api/risks/workflow/:id/assessment/review
   */
  @Post(':id/assessment/review')
  @HttpCode(HttpStatus.OK)
  @RequirePermission(Resource.RISK, Action.UPDATE)
  async reviewAssessment(
    @Param('id') id: string,
    @Body() dto: GrcReviewDto,
    @User() user: UserContext
  ) {
    return this.workflowService.reviewAssessment(
      id,
      user.organizationId,
      dto,
      user.userId,
      user.email
    );
  }

  /**
   * Submit GRC revision (GRC SME revises assessment)
   * POST /api/risks/workflow/:id/assessment/revision
   */
  @Post(':id/assessment/revision')
  @HttpCode(HttpStatus.OK)
  @RequirePermission(Resource.RISK, Action.UPDATE)
  async submitGrcRevision(
    @Param('id') id: string,
    @Body() dto: SubmitAssessmentDto,
    @User() user: UserContext
  ) {
    return this.workflowService.submitGrcRevision(
      id,
      user.organizationId,
      dto,
      user.userId,
      user.email
    );
  }

  // ===========================================
  // Risk Treatment
  // ===========================================

  /**
   * Submit treatment decision (Risk Owner)
   * POST /api/risks/workflow/:id/treatment/decision
   */
  @Post(':id/treatment/decision')
  @HttpCode(HttpStatus.OK)
  @RequirePermission(Resource.RISK, Action.UPDATE)
  async submitTreatmentDecision(
    @Param('id') id: string,
    @Body() dto: SubmitTreatmentDecisionDto,
    @User() user: UserContext
  ) {
    return this.workflowService.submitTreatmentDecision(
      id,
      user.organizationId,
      dto,
      user.userId,
      user.email
    );
  }

  /**
   * Set executive approver (GRC SME)
   * POST /api/risks/workflow/:id/treatment/set-approver
   */
  @Post(':id/treatment/set-approver')
  @HttpCode(HttpStatus.OK)
  @RequirePermission(Resource.RISK, Action.UPDATE)
  async setExecutiveApprover(
    @Param('id') id: string,
    @Body() dto: SetExecutiveApproverDto,
    @User() user: UserContext
  ) {
    return this.workflowService.setExecutiveApprover(
      id,
      user.organizationId,
      dto,
      user.userId,
      user.email
    );
  }

  /**
   * Submit executive decision (Executive Approver)
   * POST /api/risks/workflow/:id/treatment/executive-decision
   */
  @Post(':id/treatment/executive-decision')
  @HttpCode(HttpStatus.OK)
  @RequirePermission(Resource.RISK, Action.UPDATE)
  async submitExecutiveDecision(
    @Param('id') id: string,
    @Body() dto: ExecutiveDecisionDto,
    @User() user: UserContext
  ) {
    return this.workflowService.submitExecutiveDecision(
      id,
      user.organizationId,
      dto,
      user.userId,
      user.email
    );
  }

  /**
   * Submit mitigation update (Risk Owner)
   * POST /api/risks/workflow/:id/treatment/mitigation-update
   */
  @Post(':id/treatment/mitigation-update')
  @HttpCode(HttpStatus.OK)
  @RequirePermission(Resource.RISK, Action.UPDATE)
  async submitMitigationUpdate(
    @Param('id') id: string,
    @Body() dto: MitigationUpdateDto,
    @User() user: UserContext
  ) {
    return this.workflowService.submitMitigationUpdate(
      id,
      user.organizationId,
      dto,
      user.userId,
      user.email
    );
  }

  // ===========================================
  // Workflow State
  // ===========================================

  /**
   * Get complete workflow state for a risk
   * GET /api/risks/workflow/:id/state
   */
  @Get(':id/state')
  @RequirePermission(Resource.RISK, Action.READ)
  async getWorkflowState(@Param('id') id: string, @User() user: UserContext) {
    return this.workflowService.getWorkflowState(id, user.organizationId);
  }
}
