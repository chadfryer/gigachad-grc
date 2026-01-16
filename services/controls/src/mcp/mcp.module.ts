import { Module, Global, forwardRef } from '@nestjs/common';
import { makeCounterProvider } from '@willsoto/nestjs-prometheus';
import { ConfigModule } from '@nestjs/config';
import { MCPClientService } from './mcp-client.service';
import { MCPWorkflowService } from './mcp-workflow.service';
import { MCPCredentialsService } from './mcp-credentials.service';
import { MCPController } from './mcp.controller';
import { AIController } from './ai.controller';
import { MCPWorkflowController } from './mcp-workflow.controller';
import { PrismaModule } from '../prisma/prisma.module';
import { AIService } from '../ai/ai.service';

@Global()
@Module({
  imports: [ConfigModule, PrismaModule],
  controllers: [MCPController, MCPWorkflowController, AIController],
  providers: [
    MCPClientService,
    MCPWorkflowService,
    MCPCredentialsService,
    AIService, // Needed for AIController
    // Metrics: track MCP workflow executions grouped by status
    makeCounterProvider({
      name: 'mcp_workflow_executions_total',
      help: 'Total number of MCP workflow executions grouped by status',
      labelNames: ['status'],
    }),
  ],
  exports: [MCPClientService, MCPWorkflowService, MCPCredentialsService],
})
export class MCPModule {}

