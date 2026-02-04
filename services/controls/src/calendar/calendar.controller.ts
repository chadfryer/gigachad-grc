import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Body,
  Param,
  Query,
  Headers,
  HttpCode,
  HttpStatus,
  UseGuards,
  Res,
} from '@nestjs/common';
import { Response } from 'express';
import { CalendarService } from './calendar.service';
import {
  CreateCalendarEventDto,
  UpdateCalendarEventDto,
  CalendarEventFilterDto,
} from './dto/calendar-event.dto';
import { PermissionGuard } from '../auth/permission.guard';
import { DevAuthGuard, User } from '../auth/dev-auth.guard';
import { RequirePermission } from '../auth/decorators/require-permission.decorator';
import { Resource, Action } from '../permissions/dto/permission.dto';
import type { UserContext } from '@gigachad-grc/shared';

@Controller('api/calendar')
@UseGuards(DevAuthGuard, PermissionGuard)
export class CalendarController {
  constructor(private readonly calendarService: CalendarService) {}

  /**
   * List all calendar events
   */
  @Get('events')
  @RequirePermission(Resource.CONTROLS, Action.READ)
  async listEvents(
    @Query() filters: CalendarEventFilterDto,
    @User() user: UserContext,
    @Headers('x-workspace-id') workspaceId?: string
  ) {
    return this.calendarService.findAll(user.organizationId, filters, workspaceId);
  }

  /**
   * Get a single calendar event by ID
   */
  @Get('events/:id')
  @RequirePermission(Resource.CONTROLS, Action.READ)
  async getEvent(@Param('id') id: string, @User() user: UserContext) {
    return this.calendarService.findOne(id, user.organizationId);
  }

  /**
   * Create a new calendar event
   */
  @Post('events')
  @RequirePermission(Resource.CONTROLS, Action.CREATE)
  async createEvent(
    @Body() dto: CreateCalendarEventDto,
    @User() user: UserContext,
    @Headers('x-workspace-id') workspaceId?: string
  ) {
    return this.calendarService.create(
      user.organizationId,
      dto,
      user.userId,
      user.email,
      workspaceId
    );
  }

  /**
   * Update a calendar event
   */
  @Put('events/:id')
  @RequirePermission(Resource.CONTROLS, Action.UPDATE)
  async updateEvent(
    @Param('id') id: string,
    @Body() dto: UpdateCalendarEventDto,
    @User() user: UserContext
  ) {
    return this.calendarService.update(id, user.organizationId, dto, user.userId, user.email);
  }

  /**
   * Delete a calendar event
   */
  @Delete('events/:id')
  @RequirePermission(Resource.CONTROLS, Action.DELETE)
  @HttpCode(HttpStatus.NO_CONTENT)
  async deleteEvent(@Param('id') id: string, @User() user: UserContext) {
    await this.calendarService.delete(id, user.organizationId, user.userId, user.email);
  }

  /**
   * Export events to iCal format
   */
  @Get('events/export/ical')
  @RequirePermission(Resource.CONTROLS, Action.READ)
  async exportIcal(
    @Res() res: Response,
    @Query() filters: CalendarEventFilterDto,
    @User() user: UserContext,
    @Headers('x-workspace-id') workspaceId?: string
  ) {
    const icalContent = await this.calendarService.exportIcal(
      user.organizationId,
      filters,
      workspaceId
    );

    res.setHeader('Content-Type', 'text/calendar; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="compliance-calendar.ics"');
    res.send(icalContent);
  }

  /**
   * Get calendar feed URL (for external calendar subscriptions)
   */
  @Get('feed')
  @RequirePermission(Resource.CONTROLS, Action.READ)
  async getCalendarFeed(@User() _user: UserContext) {
    // Return the URL that external calendars can subscribe to
    const baseUrl = process.env.API_URL || 'http://localhost:3000';
    return {
      feedUrl: `${baseUrl}/api/calendar/events/export/ical`,
      instructions: 'Subscribe to this URL in your calendar app to receive automated updates.',
    };
  }
}
