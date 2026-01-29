import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Body,
  Param,
  Query,
  UseGuards,
  Request,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { WorkspaceService } from './workspace.service';
import {
  CreateWorkspaceDto,
  UpdateWorkspaceDto,
  AddWorkspaceMemberDto,
  UpdateWorkspaceMemberDto,
  WorkspaceFilterDto,
  EnableMultiWorkspaceDto,
} from './dto/workspace.dto';
import { DevAuthGuard } from '../auth/dev-auth.guard';
import { PermissionGuard } from '../auth/permission.guard';
import { RequirePermission } from '../auth/decorators/require-permission.decorator';
import { Resource, Action } from '../permissions/dto/permission.dto';

@Controller('api/workspaces')
@UseGuards(DevAuthGuard, PermissionGuard)
export class WorkspaceController {
  constructor(private readonly workspaceService: WorkspaceService) {}

  /**
   * Check if multi-workspace mode is enabled for the organization
   */
  @Get('status')
  async getMultiWorkspaceStatus(@Request() req: any) {
    const enabled = await this.workspaceService.isMultiWorkspaceEnabled(req.user.organizationId);
    return { enabled };
  }

  /**
   * Enable or disable multi-workspace mode (admin only)
   */
  @Post('toggle')
  @RequirePermission(Resource.WORKSPACES, Action.UPDATE)
  async toggleMultiWorkspace(@Request() req: any, @Body() dto: EnableMultiWorkspaceDto) {
    return this.workspaceService.toggleMultiWorkspace(
      req.user.organizationId,
      dto.enabled,
      req.user.id
    );
  }

  /**
   * List all workspaces (filtered by user access for non-admins)
   */
  @Get()
  async findAll(@Request() req: any, @Query() filters: WorkspaceFilterDto) {
    return this.workspaceService.findAll(
      req.user.organizationId,
      req.user.id,
      req.user.role,
      filters
    );
  }

  /**
   * Get org-level consolidated dashboard (admin only)
   */
  @Get('org/dashboard')
  @RequirePermission(Resource.WORKSPACES, Action.READ)
  async getOrgDashboard(@Request() req: any) {
    return this.workspaceService.getOrgDashboard(req.user.organizationId);
  }

  /**
   * Get a single workspace by ID
   */
  @Get(':id')
  async findOne(@Param('id') id: string, @Request() req: any) {
    return this.workspaceService.findOne(id, req.user.organizationId, req.user.id, req.user.role);
  }

  /**
   * Get workspace dashboard
   */
  @Get(':id/dashboard')
  async getDashboard(@Param('id') id: string, @Request() req: any) {
    return this.workspaceService.getDashboard(
      id,
      req.user.organizationId,
      req.user.id,
      req.user.role
    );
  }

  /**
   * Create a new workspace (admin only)
   */
  @Post()
  @RequirePermission(Resource.WORKSPACES, Action.CREATE)
  async create(@Request() req: any, @Body() dto: CreateWorkspaceDto) {
    return this.workspaceService.create(req.user.organizationId, req.user.id, dto);
  }

  /**
   * Update a workspace
   */
  @Put(':id')
  @RequirePermission(Resource.WORKSPACES, Action.UPDATE)
  async update(@Param('id') id: string, @Request() req: any, @Body() dto: UpdateWorkspaceDto) {
    return this.workspaceService.update(id, req.user.organizationId, dto);
  }

  /**
   * Delete (archive) a workspace
   */
  @Delete(':id')
  @RequirePermission(Resource.WORKSPACES, Action.DELETE)
  @HttpCode(HttpStatus.NO_CONTENT)
  async remove(@Param('id') id: string, @Request() req: any) {
    await this.workspaceService.remove(id, req.user.organizationId);
  }

  /**
   * List workspace members
   */
  @Get(':id/members')
  async listMembers(@Param('id') id: string, @Request() req: any) {
    const workspace = await this.workspaceService.findOne(
      id,
      req.user.organizationId,
      req.user.id,
      req.user.role
    );
    return workspace.members;
  }

  /**
   * Add a member to a workspace
   */
  @Post(':id/members')
  @RequirePermission(Resource.WORKSPACES, Action.ASSIGN)
  async addMember(
    @Param('id') id: string,
    @Request() req: any,
    @Body() dto: AddWorkspaceMemberDto
  ) {
    return this.workspaceService.addMember(id, req.user.organizationId, dto);
  }

  /**
   * Update a member's role
   */
  @Put(':id/members/:userId')
  @RequirePermission(Resource.WORKSPACES, Action.ASSIGN)
  async updateMember(
    @Param('id') id: string,
    @Param('userId') userId: string,
    @Request() req: any,
    @Body() dto: UpdateWorkspaceMemberDto
  ) {
    return this.workspaceService.updateMember(id, userId, req.user.organizationId, dto);
  }

  /**
   * Remove a member from a workspace
   */
  @Delete(':id/members/:userId')
  @RequirePermission(Resource.WORKSPACES, Action.DELETE)
  @HttpCode(HttpStatus.NO_CONTENT)
  async removeMember(
    @Param('id') id: string,
    @Param('userId') userId: string,
    @Request() req: any
  ) {
    await this.workspaceService.removeMember(id, userId, req.user.organizationId);
  }
}
