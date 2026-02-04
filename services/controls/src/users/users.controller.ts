import {
  Controller,
  Get,
  Post,
  Put,
  Body,
  Param,
  Query,
  HttpCode,
  HttpStatus,
  UseGuards,
  ParseUUIDPipe,
} from '@nestjs/common';
import { UsersService } from './users.service';
import { PermissionsService } from '../permissions/permissions.service';
import { GroupsService } from '../permissions/groups.service';
import {
  CreateUserDto,
  UpdateUserDto,
  SyncUserFromKeycloakDto,
  UserFilterDto,
} from './dto/user.dto';
import { PermissionGuard } from '../auth/permission.guard';
import { DevAuthGuard, User } from '../auth/dev-auth.guard';
import { RequirePermission } from '../auth/decorators/require-permission.decorator';
import { Resource, Action } from '../permissions/dto/permission.dto';
import { PaginationLimitPipe, PaginationPagePipe } from '../common/pagination.pipe';
import type { UserContext } from '@gigachad-grc/shared';

@Controller('api/users')
@UseGuards(DevAuthGuard, PermissionGuard)
export class UsersController {
  constructor(
    private readonly usersService: UsersService,
    private readonly permissionsService: PermissionsService,
    private readonly groupsService: GroupsService
  ) {}

  // ===========================
  // User CRUD
  // ===========================

  @Get()
  @RequirePermission(Resource.USERS, Action.READ)
  async listUsers(
    @Query() filters: UserFilterDto,
    @Query('page', new PaginationPagePipe()) page: number,
    @Query('limit', new PaginationLimitPipe({ default: 50 })) limit: number,
    @User() user: UserContext
  ) {
    return this.usersService.findAll(user.organizationId, filters, page, limit);
  }

  @Get('stats')
  @RequirePermission(Resource.USERS, Action.READ)
  async getUserStats(@User() user: UserContext) {
    return this.usersService.getStats(user.organizationId);
  }

  @Get('me')
  async getCurrentUser(@User() user: UserContext) {
    if (!user.userId) {
      return null;
    }

    try {
      const currentUser = await this.usersService.findOne(user.userId, user.organizationId);
      const permissions = await this.permissionsService.getUserPermissions(
        user.userId,
        user.organizationId
      );
      return { ...currentUser, permissions };
    } catch {
      return null;
    }
  }

  @Get(':id')
  @RequirePermission(Resource.USERS, Action.READ)
  async getUser(@Param('id', ParseUUIDPipe) id: string, @User() user: UserContext) {
    return this.usersService.findOne(id, user.organizationId);
  }

  @Get(':id/permissions')
  @RequirePermission(Resource.USERS, Action.READ)
  async getUserPermissions(@Param('id', ParseUUIDPipe) id: string, @User() user: UserContext) {
    return this.permissionsService.getUserPermissions(id, user.organizationId);
  }

  @Post()
  @RequirePermission(Resource.USERS, Action.CREATE)
  async createUser(@Body() dto: CreateUserDto, @User() user: UserContext) {
    return this.usersService.create(user.organizationId, dto, user.userId, user.email);
  }

  @Put(':id')
  @RequirePermission(Resource.USERS, Action.UPDATE)
  async updateUser(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: UpdateUserDto,
    @User() user: UserContext
  ) {
    return this.usersService.update(id, user.organizationId, dto, user.userId, user.email);
  }

  @Post(':id/deactivate')
  @RequirePermission(Resource.USERS, Action.UPDATE)
  @HttpCode(HttpStatus.NO_CONTENT)
  async deactivateUser(@Param('id', ParseUUIDPipe) id: string, @User() user: UserContext) {
    await this.usersService.deactivate(id, user.organizationId, user.userId, user.email);
  }

  @Post(':id/reactivate')
  @RequirePermission(Resource.USERS, Action.UPDATE)
  @HttpCode(HttpStatus.NO_CONTENT)
  async reactivateUser(@Param('id', ParseUUIDPipe) id: string, @User() user: UserContext) {
    await this.usersService.reactivate(id, user.organizationId, user.userId, user.email);
  }

  // ===========================
  // User Groups
  // ===========================

  @Get(':id/groups')
  @RequirePermission(Resource.USERS, Action.READ)
  async getUserGroups(@Param('id', ParseUUIDPipe) id: string, @User() user: UserContext) {
    const targetUser = await this.usersService.findOne(id, user.organizationId);
    return targetUser.groups;
  }

  @Post(':id/groups/:groupId')
  @RequirePermission(Resource.PERMISSIONS, Action.UPDATE)
  @HttpCode(HttpStatus.CREATED)
  async addUserToGroup(
    @Param('id', ParseUUIDPipe) userId: string,
    @Param('groupId', ParseUUIDPipe) groupId: string,
    @User() user: UserContext
  ) {
    await this.groupsService.addMember(
      groupId,
      userId,
      user.organizationId,
      user.userId,
      user.email
    );
    return { success: true };
  }

  @Post(':id/groups/:groupId/remove')
  @RequirePermission(Resource.PERMISSIONS, Action.UPDATE)
  @HttpCode(HttpStatus.NO_CONTENT)
  async removeUserFromGroup(
    @Param('id', ParseUUIDPipe) userId: string,
    @Param('groupId', ParseUUIDPipe) groupId: string,
    @User() user: UserContext
  ) {
    await this.groupsService.removeMember(
      groupId,
      userId,
      user.organizationId,
      user.userId,
      user.email
    );
  }

  // ===========================
  // Keycloak Sync
  // ===========================

  @Post('sync')
  async syncFromKeycloak(@Body() dto: SyncUserFromKeycloakDto, @User() user: UserContext) {
    return this.usersService.syncFromKeycloak(user.organizationId, dto);
  }

  @Get('keycloak/:keycloakId')
  @RequirePermission(Resource.USERS, Action.READ)
  async getUserByKeycloakId(@Param('keycloakId') keycloakId: string, @User() user: UserContext) {
    // SECURITY: Filter by organizationId to prevent IDOR - users can only lookup
    // Keycloak users within their own organization
    return this.usersService.findByKeycloakId(keycloakId, user.organizationId);
  }
}
