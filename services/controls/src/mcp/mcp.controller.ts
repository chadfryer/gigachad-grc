import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
  ApiBody,
  ApiParam,
} from '@nestjs/swagger';
import { MCPClientService } from './mcp-client.service';
import { DevAuthGuard } from '../auth/dev-auth.guard';
import { PermissionGuard } from '../auth/permission.guard';
import { RequirePermission } from '../auth/decorators/require-permission.decorator';
import { Resource, Action } from '../permissions/dto/permission.dto';
import { CallToolDto, GetPromptDto, ReadResourceDto } from './dto/mcp.dto';

@ApiTags('MCP Servers')
@ApiBearerAuth()
@Controller('api/mcp')
@UseGuards(DevAuthGuard, PermissionGuard)
export class MCPController {
  constructor(private readonly mcpClient: MCPClientService) {}

  // ============================================
  // Server Management
  // ============================================

  @Get('servers')
  @ApiOperation({ summary: 'List all MCP servers and their status' })
  @ApiResponse({
    status: 200,
    description: 'List of servers',
    schema: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          name: { type: 'string' },
          status: { type: 'string' },
          description: { type: 'string' },
        },
      },
    },
  })
  @RequirePermission(Resource.INTEGRATIONS, Action.READ)
  getServers() {
    return this.mcpClient.getServers();
  }

  @Get('servers/:serverId/status')
  @ApiOperation({ summary: 'Get detailed status of an MCP server' })
  @ApiParam({ name: 'serverId', description: 'Server ID' })
  @RequirePermission(Resource.INTEGRATIONS, Action.READ)
  getServerStatus(@Param('serverId') serverId: string) {
    const status = this.mcpClient.getServerStatus(serverId);
    if (!status) {
      return { error: 'Server not found' };
    }
    return {
      id: status.config.id,
      name: status.config.name,
      status: status.status,
      startedAt: status.startedAt,
      lastError: status.lastError,
      restartCount: status.restartCount,
      capabilities: status.config.capabilities,
    };
  }

  @Post('servers/:serverId/start')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Start an MCP server' })
  @ApiParam({ name: 'serverId', description: 'Server ID' })
  @RequirePermission(Resource.INTEGRATIONS, Action.UPDATE)
  async startServer(@Param('serverId') serverId: string) {
    await this.mcpClient.startServer(serverId);
    return { success: true, message: `Server ${serverId} started` };
  }

  @Post('servers/:serverId/stop')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Stop an MCP server' })
  @ApiParam({ name: 'serverId', description: 'Server ID' })
  @RequirePermission(Resource.INTEGRATIONS, Action.UPDATE)
  async stopServer(@Param('serverId') serverId: string) {
    await this.mcpClient.stopServer(serverId);
    return { success: true, message: `Server ${serverId} stopped` };
  }

  @Post('servers/:serverId/restart')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Restart an MCP server' })
  @ApiParam({ name: 'serverId', description: 'Server ID' })
  @RequirePermission(Resource.INTEGRATIONS, Action.UPDATE)
  async restartServer(@Param('serverId') serverId: string) {
    await this.mcpClient.restartServer(serverId);
    return { success: true, message: `Server ${serverId} restarted` };
  }

  // ============================================
  // Tools
  // ============================================

  @Get('servers/:serverId/tools')
  @ApiOperation({ summary: 'List available tools for a server' })
  @ApiParam({ name: 'serverId', description: 'Server ID' })
  @RequirePermission(Resource.INTEGRATIONS, Action.READ)
  getServerTools(@Param('serverId') serverId: string) {
    return this.mcpClient.getTools(serverId);
  }

  @Get('tools')
  @ApiOperation({ summary: 'List all available tools across all servers' })
  @RequirePermission(Resource.INTEGRATIONS, Action.READ)
  getAllTools() {
    return this.mcpClient.getAllTools();
  }

  @Post('servers/:serverId/tools/call')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Call a tool on an MCP server' })
  @ApiParam({ name: 'serverId', description: 'Server ID' })
  @ApiBody({ type: CallToolDto })
  @RequirePermission(Resource.INTEGRATIONS, Action.CREATE)
  async callTool(
    @Param('serverId') serverId: string,
    @Body() dto: CallToolDto
  ) {
    const result = await this.mcpClient.callTool(serverId, dto.toolName, dto.params);
    return { result };
  }

  // ============================================
  // Resources
  // ============================================

  @Get('servers/:serverId/resources')
  @ApiOperation({ summary: 'List resources from an MCP server' })
  @ApiParam({ name: 'serverId', description: 'Server ID' })
  @RequirePermission(Resource.INTEGRATIONS, Action.READ)
  async listResources(@Param('serverId') serverId: string) {
    return this.mcpClient.listResources(serverId);
  }

  @Post('servers/:serverId/resources/read')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Read a resource from an MCP server' })
  @ApiParam({ name: 'serverId', description: 'Server ID' })
  @ApiBody({ type: ReadResourceDto })
  @RequirePermission(Resource.INTEGRATIONS, Action.READ)
  async readResource(
    @Param('serverId') serverId: string,
    @Body() dto: ReadResourceDto
  ) {
    return this.mcpClient.readResource(serverId, dto.uri);
  }

  // ============================================
  // Prompts
  // ============================================

  @Get('servers/:serverId/prompts')
  @ApiOperation({ summary: 'List prompts from an MCP server' })
  @ApiParam({ name: 'serverId', description: 'Server ID' })
  @RequirePermission(Resource.AI, Action.READ)
  async listPrompts(@Param('serverId') serverId: string) {
    return this.mcpClient.listPrompts(serverId);
  }

  @Post('servers/:serverId/prompts/get')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Get a prompt from an MCP server' })
  @ApiParam({ name: 'serverId', description: 'Server ID' })
  @ApiBody({ type: GetPromptDto })
  @RequirePermission(Resource.AI, Action.READ)
  async getPrompt(
    @Param('serverId') serverId: string,
    @Body() dto: GetPromptDto
  ) {
    return this.mcpClient.getPrompt(serverId, dto.name, dto.args);
  }
}
