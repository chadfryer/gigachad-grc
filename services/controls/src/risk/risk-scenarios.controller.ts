import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Body,
  Param,
  Query,
  HttpCode,
  HttpStatus,
  ValidationPipe,
  UseGuards,
} from '@nestjs/common';
import { RiskScenariosService } from './risk-scenarios.service';
import { DevAuthGuard, User } from '../auth/dev-auth.guard';
import type { UserContext } from '@gigachad-grc/shared';
import { PermissionGuard } from '../auth/permission.guard';
import { RequirePermission } from '../auth/decorators/require-permission.decorator';
import { Resource, Action } from '../permissions/dto/permission.dto';
import {
  CreateRiskScenarioDto,
  UpdateRiskScenarioDto,
  ListRiskScenariosQueryDto,
  CloneScenarioDto,
} from './dto/risk-scenario.dto';

@Controller('api/risk-scenarios')
@UseGuards(DevAuthGuard, PermissionGuard)
export class RiskScenariosController {
  constructor(private readonly riskScenariosService: RiskScenariosService) {}

  @Get()
  @RequirePermission(Resource.RISK, Action.READ)
  async list(
    @User() user: UserContext,
    @Query(new ValidationPipe({ transform: true })) query: ListRiskScenariosQueryDto
  ) {
    return this.riskScenariosService.listScenarios(user.organizationId, query);
  }

  @Get('templates')
  @RequirePermission(Resource.RISK, Action.READ)
  async getTemplates(@User() user: UserContext) {
    return this.riskScenariosService.getTemplates(user.organizationId);
  }

  @Get('library')
  @RequirePermission(Resource.RISK, Action.READ)
  async getLibrary() {
    // Get global library templates available to all organizations
    return this.riskScenariosService.getLibraryTemplates();
  }

  @Get('library/by-category')
  @RequirePermission(Resource.RISK, Action.READ)
  async getLibraryByCategory() {
    // Get library templates grouped by category
    return this.riskScenariosService.getLibraryByCategory();
  }

  @Get('categories')
  @RequirePermission(Resource.RISK, Action.READ)
  async getCategories(@User() user: UserContext) {
    return this.riskScenariosService.getCategories(user.organizationId);
  }

  @Get('statistics')
  @RequirePermission(Resource.RISK, Action.READ)
  async getStatistics(@User() user: UserContext) {
    return this.riskScenariosService.getStatistics(user.organizationId);
  }

  @Get(':id')
  @RequirePermission(Resource.RISK, Action.READ)
  async get(@User() user: UserContext, @Param('id') id: string) {
    return this.riskScenariosService.getScenario(user.organizationId, id);
  }

  @Post()
  @HttpCode(HttpStatus.CREATED)
  @RequirePermission(Resource.RISK, Action.CREATE)
  async create(
    @User() user: UserContext,
    @Body(new ValidationPipe({ transform: true })) dto: CreateRiskScenarioDto
  ) {
    return this.riskScenariosService.createScenario(user.organizationId, user.userId, dto);
  }

  @Put(':id')
  @RequirePermission(Resource.RISK, Action.UPDATE)
  async update(
    @User() user: UserContext,
    @Param('id') id: string,
    @Body(new ValidationPipe({ transform: true })) dto: UpdateRiskScenarioDto
  ) {
    return this.riskScenariosService.updateScenario(user.organizationId, user.userId, id, dto);
  }

  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  @RequirePermission(Resource.RISK, Action.DELETE)
  async delete(@User() user: UserContext, @Param('id') id: string) {
    return this.riskScenariosService.deleteScenario(user.organizationId, user.userId, id);
  }

  @Post(':id/clone')
  @RequirePermission(Resource.RISK, Action.CREATE)
  async clone(@User() user: UserContext, @Param('id') id: string, @Body() dto: CloneScenarioDto) {
    return this.riskScenariosService.cloneScenario(
      user.organizationId,
      user.userId,
      id,
      dto.newTitle
    );
  }

  @Post(':id/simulate')
  @RequirePermission(Resource.RISK, Action.UPDATE)
  async simulate(
    @User() user: UserContext,
    @Param('id') id: string,
    @Body() body: { controlEffectiveness?: number; mitigations?: string[] }
  ) {
    return this.riskScenariosService.runSimulation(user.organizationId, id, body);
  }

  @Post('bulk/from-templates')
  @RequirePermission(Resource.RISK, Action.CREATE)
  async bulkCreateFromTemplates(
    @User() user: UserContext,
    @Body() body: { templateIds: string[] }
  ) {
    return this.riskScenariosService.bulkCreateFromTemplates(
      user.organizationId,
      user.userId,
      body.templateIds
    );
  }
}
