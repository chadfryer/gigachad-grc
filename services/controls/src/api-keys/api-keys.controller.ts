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
  UseGuards,
  ParseUUIDPipe,
} from '@nestjs/common';
import { ApiKeysService } from './api-keys.service';
import {
  CreateApiKeyDto,
  UpdateApiKeyDto,
  ApiKeyFilterDto,
  API_KEY_SCOPES,
} from './dto/api-key.dto';
import { PermissionGuard } from '../auth/permission.guard';
import { DevAuthGuard, User } from '../auth/dev-auth.guard';
import { RequirePermission } from '../auth/decorators/require-permission.decorator';
import { Resource, Action } from '../permissions/dto/permission.dto';
import { PaginationLimitPipe, PaginationPagePipe } from '../common/pagination.pipe';
import { EndpointRateLimit, ENDPOINT_RATE_LIMITS } from '@gigachad-grc/shared';
import type { UserContext } from '@gigachad-grc/shared';

@Controller('api/api-keys')
@UseGuards(DevAuthGuard, PermissionGuard)
export class ApiKeysController {
  constructor(private readonly apiKeysService: ApiKeysService) {}

  /**
   * List all API keys for the organization
   */
  @Get()
  @RequirePermission(Resource.SETTINGS, Action.READ)
  async listApiKeys(
    @Query() filters: ApiKeyFilterDto,
    @Query('page', new PaginationPagePipe()) page: number,
    @Query('limit', new PaginationLimitPipe({ default: 50 })) limit: number,
    @User() user: UserContext
  ) {
    return this.apiKeysService.findAll(user.organizationId, filters, page, limit);
  }

  /**
   * Get API key statistics
   */
  @Get('stats')
  @RequirePermission(Resource.SETTINGS, Action.READ)
  async getApiKeyStats(@User() user: UserContext) {
    return this.apiKeysService.getStats(user.organizationId);
  }

  /**
   * Get available scopes
   */
  @Get('scopes')
  @RequirePermission(Resource.SETTINGS, Action.READ)
  async getAvailableScopes() {
    return {
      scopes: API_KEY_SCOPES,
    };
  }

  /**
   * Get a single API key by ID
   */
  @Get(':id')
  @RequirePermission(Resource.SETTINGS, Action.READ)
  async getApiKey(@Param('id', ParseUUIDPipe) id: string, @User() user: UserContext) {
    return this.apiKeysService.findOne(id, user.organizationId);
  }

  /**
   * Create a new API key
   * The full key is only returned once - store it securely
   */
  @Post()
  @EndpointRateLimit(ENDPOINT_RATE_LIMITS.API_KEY)
  @RequirePermission(Resource.SETTINGS, Action.CREATE)
  async createApiKey(@Body() dto: CreateApiKeyDto, @User() user: UserContext) {
    return this.apiKeysService.create(user.organizationId, dto, user.userId, user.email);
  }

  /**
   * Update an API key
   */
  @Put(':id')
  @RequirePermission(Resource.SETTINGS, Action.UPDATE)
  async updateApiKey(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: UpdateApiKeyDto,
    @User() user: UserContext
  ) {
    return this.apiKeysService.update(id, user.organizationId, dto, user.userId, user.email);
  }

  /**
   * Revoke an API key (deactivate without deleting)
   */
  @Post(':id/revoke')
  @RequirePermission(Resource.SETTINGS, Action.UPDATE)
  @HttpCode(HttpStatus.NO_CONTENT)
  async revokeApiKey(@Param('id', ParseUUIDPipe) id: string, @User() user: UserContext) {
    await this.apiKeysService.revoke(id, user.organizationId, user.userId, user.email);
  }

  /**
   * Regenerate an API key
   * Creates a new key value, invalidating the old one
   * The new key is only returned once
   */
  @Post(':id/regenerate')
  @EndpointRateLimit(ENDPOINT_RATE_LIMITS.API_KEY)
  @RequirePermission(Resource.SETTINGS, Action.UPDATE)
  async regenerateApiKey(@Param('id', ParseUUIDPipe) id: string, @User() user: UserContext) {
    return this.apiKeysService.regenerate(id, user.organizationId, user.userId, user.email);
  }

  /**
   * Delete an API key permanently
   */
  @Delete(':id')
  @RequirePermission(Resource.SETTINGS, Action.DELETE)
  @HttpCode(HttpStatus.NO_CONTENT)
  async deleteApiKey(@Param('id', ParseUUIDPipe) id: string, @User() user: UserContext) {
    await this.apiKeysService.delete(id, user.organizationId, user.userId, user.email);
  }
}
