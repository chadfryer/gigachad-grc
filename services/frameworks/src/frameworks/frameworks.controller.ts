import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Param,
  Query,
  Body,
  UseGuards,
  UseInterceptors,
  UploadedFile,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiParam,
  ApiBody,
  ApiProperty,
} from '@nestjs/swagger';
import { IsString, IsOptional, IsBoolean, IsNumber } from 'class-validator';
import { FrameworksService } from './frameworks.service';
import { CurrentUser, UserContext } from '@gigachad-grc/shared';
import { DevAuthGuard } from '../auth/dev-auth.guard';

class CreateFrameworkDto {
  @ApiProperty()
  @IsString()
  name: string;

  @ApiProperty()
  @IsString()
  type: string;

  @ApiProperty({ required: false })
  @IsString()
  @IsOptional()
  version?: string;

  @ApiProperty({ required: false })
  @IsString()
  @IsOptional()
  description?: string;

  @ApiProperty({ required: false, default: true })
  @IsBoolean()
  @IsOptional()
  isActive?: boolean;
}

class CreateRequirementDto {
  @ApiProperty()
  @IsString()
  reference: string;

  @ApiProperty()
  @IsString()
  title: string;

  @ApiProperty()
  @IsString()
  description: string;

  @ApiProperty({ required: false })
  @IsString()
  @IsOptional()
  guidance?: string;

  @ApiProperty({ required: false })
  @IsString()
  @IsOptional()
  parentId?: string;

  @ApiProperty({ required: false, default: false })
  @IsBoolean()
  @IsOptional()
  isCategory?: boolean;

  @ApiProperty({ required: false, default: 0 })
  @IsNumber()
  @IsOptional()
  order?: number;
}

class UpdateRequirementOwnerDto {
  ownerId?: string | null;
  ownerNotes?: string;
  dueDate?: string;
  priority?: string;
}

@ApiTags('frameworks')
@ApiBearerAuth()
@Controller('api/frameworks')
export class FrameworksController {
  constructor(private readonly frameworksService: FrameworksService) {}

  @Get()
  @UseGuards(DevAuthGuard)
  @ApiOperation({ summary: 'List all frameworks' })
  @ApiResponse({ status: 200, description: 'Returns list of frameworks with readiness' })
  async findAll(@CurrentUser() user: UserContext) {
    return this.frameworksService.findAll(user.organizationId);
  }

  @Post()
  @UseGuards(DevAuthGuard)
  @ApiOperation({ summary: 'Create a new framework' })
  @ApiResponse({ status: 201, description: 'Framework created successfully' })
  @ApiBody({ type: CreateFrameworkDto })
  async create(@CurrentUser() user: UserContext, @Body() dto: CreateFrameworkDto) {
    return this.frameworksService.create(user.organizationId, dto);
  }

  @Get('types')
  @UseGuards(DevAuthGuard)
  @ApiOperation({ summary: 'Get framework types' })
  async getTypes() {
    return this.frameworksService.getFrameworkTypes();
  }

  @Get(':id')
  @UseGuards(DevAuthGuard)
  @ApiOperation({ summary: 'Get framework by ID' })
  @ApiParam({ name: 'id', description: 'Framework ID' })
  async findOne(@Param('id') id: string, @CurrentUser() user: UserContext) {
    // SECURITY: Validate framework belongs to user's organization
    return this.frameworksService.findOne(id, user.organizationId);
  }

  @Put(':id')
  @UseGuards(DevAuthGuard)
  @ApiOperation({ summary: 'Update a framework' })
  @ApiParam({ name: 'id', description: 'Framework ID' })
  @ApiBody({ type: CreateFrameworkDto })
  @ApiResponse({ status: 200, description: 'Framework updated successfully' })
  async update(@Param('id') id: string, @Body() dto: CreateFrameworkDto) {
    return this.frameworksService.update(id, dto);
  }

  @Delete(':id')
  @UseGuards(DevAuthGuard)
  @ApiOperation({ summary: 'Delete a framework (soft delete)' })
  @ApiParam({ name: 'id', description: 'Framework ID' })
  @ApiResponse({ status: 200, description: 'Framework deleted successfully' })
  async delete(@Param('id') id: string, @CurrentUser() user: UserContext) {
    return this.frameworksService.delete(id, user.userId);
  }

  @Get(':id/requirements')
  @UseGuards(DevAuthGuard)
  @ApiOperation({ summary: 'Get framework requirements' })
  @ApiParam({ name: 'id', description: 'Framework ID' })
  async getRequirements(
    @Param('id') id: string,
    @Query('parentId') parentId?: string,
    @CurrentUser() user: UserContext
  ) {
    // SECURITY: Validate framework belongs to user's organization before returning requirements
    return this.frameworksService.getRequirements(id, parentId, user.organizationId);
  }

  @Post(':id/requirements')
  @UseGuards(DevAuthGuard)
  @ApiOperation({ summary: 'Create a framework requirement' })
  @ApiParam({ name: 'id', description: 'Framework ID' })
  @ApiBody({ type: CreateRequirementDto })
  @ApiResponse({ status: 201, description: 'Requirement created successfully' })
  async createRequirement(@Param('id') id: string, @Body() dto: CreateRequirementDto) {
    return this.frameworksService.createRequirement(id, dto);
  }

  @Post(':id/requirements/bulk-upload')
  @UseGuards(DevAuthGuard)
  @UseInterceptors(FileInterceptor('file'))
  @ApiOperation({ summary: 'Bulk upload requirements from CSV, Excel, or JSON file' })
  @ApiParam({ name: 'id', description: 'Framework ID' })
  @ApiResponse({ status: 201, description: 'Requirements uploaded successfully' })
  async bulkUploadRequirements(@Param('id') id: string, @UploadedFile() file: Express.Multer.File) {
    return this.frameworksService.bulkUploadRequirements(id, file);
  }

  @Get(':id/requirements/tree')
  @UseGuards(DevAuthGuard)
  @ApiOperation({ summary: 'Get framework requirements as tree' })
  @ApiParam({ name: 'id', description: 'Framework ID' })
  async getRequirementTree(@Param('id') id: string, @CurrentUser() user: UserContext) {
    return this.frameworksService.getRequirementTree(id, user.organizationId);
  }

  @Get(':id/requirements/:requirementId')
  @UseGuards(DevAuthGuard)
  @ApiOperation({ summary: 'Get specific requirement' })
  async getRequirement(
    @Param('id') id: string,
    @Param('requirementId') requirementId: string,
    @CurrentUser() user: UserContext
  ) {
    // SECURITY: Validate framework belongs to user's organization before returning requirement
    return this.frameworksService.getRequirement(id, requirementId, user.organizationId);
  }

  @Put(':id/requirements/:requirementId')
  @UseGuards(DevAuthGuard)
  @ApiOperation({ summary: 'Update requirement (owner, notes, due date, priority)' })
  @ApiParam({ name: 'id', description: 'Framework ID' })
  @ApiParam({ name: 'requirementId', description: 'Requirement ID' })
  @ApiBody({ type: UpdateRequirementOwnerDto })
  async updateRequirement(
    @Param('id') id: string,
    @Param('requirementId') requirementId: string,
    @Body() dto: UpdateRequirementOwnerDto
  ) {
    return this.frameworksService.updateRequirement(id, requirementId, dto);
  }

  @Get(':id/readiness')
  @UseGuards(DevAuthGuard)
  @ApiOperation({ summary: 'Calculate framework readiness score' })
  @ApiParam({ name: 'id', description: 'Framework ID' })
  async getReadiness(@Param('id') id: string, @CurrentUser() user: UserContext) {
    return this.frameworksService.calculateReadiness(id, user.organizationId);
  }
}

@ApiTags('users')
@ApiBearerAuth()
@Controller('api/users')
@UseGuards(DevAuthGuard)
export class UsersController {
  constructor(private readonly frameworksService: FrameworksService) {}

  @Get()
  @ApiOperation({ summary: 'List users for owner assignment' })
  async listUsers(@CurrentUser() user: UserContext) {
    return this.frameworksService.listUsers(user.organizationId);
  }
}
