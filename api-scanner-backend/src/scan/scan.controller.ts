import { Controller, Post, Body, BadRequestException } from '@nestjs/common';
import { ScanXSSService, ScanSQLiService } from './scan.service';
import { ScanXSSResult } from '../dto/XSS.dto';
import { ScanSQLInjectionResult } from '../dto/SQLInjection.dto';

@Controller('scan')
export class ScanController {
  constructor(
    private readonly scanService: ScanXSSService,
    private readonly sqliService: ScanSQLiService,
  ) {}

  @Post('xss')
  async scanXSS(@Body('url') url: string): Promise<ScanXSSResult[]> {
    if (!url || typeof url !== 'string') {
      throw new BadRequestException('URL is required');
    }

    try {
      new URL(url);
    } catch {
      throw new BadRequestException('Invalid URL format');
    }

    return this.scanService.scanForXSS(url);
  }

  @Post('sql')
  async scanSQLi(@Body('url') url: string): Promise<ScanSQLInjectionResult[]> {
    if (!url || typeof url !== 'string') {
      throw new BadRequestException('URL is required');
    }

    try {
      new URL(url);
    } catch {
      throw new BadRequestException('Invalid URL format');
    }

    return this.sqliService.scanForSQLi(url);
  }
}
