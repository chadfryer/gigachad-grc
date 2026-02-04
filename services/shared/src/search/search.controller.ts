import { Controller, Get, Query, UseGuards } from '@nestjs/common';
import { SearchService } from './search.service';
import { DevAuthGuard } from '../auth/dev-auth.guard';

/**
 * SECURITY: This controller requires authentication at the class level.
 * All endpoints will require a valid authenticated user context.
 */
@Controller('search')
@UseGuards(DevAuthGuard)
export class SearchController {
  constructor(private readonly searchService: SearchService) {}

  @Get('global')
  async globalSearch(@Query('q') query: string) {
    if (!query || query.length < 2) {
      return { data: [] };
    }

    const results = await this.searchService.searchAll(query);
    return { data: results };
  }
}
