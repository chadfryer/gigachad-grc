import { Controller, Get, Put, Post, Delete, Body, Param, UseGuards } from '@nestjs/common';
import { RiskConfigService } from './risk-config.service';
import { UpdateRiskConfigurationDto, RiskCategoryDto } from './dto/risk-config.dto';
import { DevAuthGuard, User } from '../auth/dev-auth.guard';
import type { UserContext } from '@gigachad-grc/shared';

@Controller('api/risk-config')
@UseGuards(DevAuthGuard)
export class RiskConfigController {
  constructor(private readonly riskConfigService: RiskConfigService) {}

  /**
   * Get risk configuration for organization
   */
  @Get()
  async getConfiguration(@User() user: UserContext) {
    return this.riskConfigService.getConfiguration(user.organizationId);
  }

  /**
   * Update risk configuration
   */
  @Put()
  async updateConfiguration(@User() user: UserContext, @Body() dto: UpdateRiskConfigurationDto) {
    return this.riskConfigService.updateConfiguration(user.organizationId, dto, user.userId);
  }

  /**
   * Reset configuration to defaults
   */
  @Post('reset')
  async resetToDefaults(@User() user: UserContext) {
    return this.riskConfigService.resetToDefaults(user.organizationId, user.userId);
  }

  /**
   * Add a new category
   */
  @Post('categories')
  async addCategory(@User() user: UserContext, @Body() category: Omit<RiskCategoryDto, 'id'>) {
    return this.riskConfigService.addCategory(user.organizationId, category, user.userId);
  }

  /**
   * Remove a category
   */
  @Delete('categories/:categoryId')
  async removeCategory(@User() user: UserContext, @Param('categoryId') categoryId: string) {
    return this.riskConfigService.removeCategory(user.organizationId, categoryId, user.userId);
  }

  /**
   * Update risk appetite for a category
   */
  @Put('appetite/:category')
  async updateRiskAppetite(
    @User() user: UserContext,
    @Param('category') category: string,
    @Body() body: { level: string; description?: string }
  ) {
    return this.riskConfigService.updateRiskAppetite(
      user.organizationId,
      category,
      body.level,
      body.description,
      user.userId
    );
  }
}
