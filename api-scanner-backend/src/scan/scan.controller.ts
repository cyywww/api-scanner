import { Controller, Post, Body, BadRequestException } from '@nestjs/common';
import { ScanXSSService, ScanSQLiService } from './scan.service';
import { ScanXSSResult } from '../dto/XSS.dto';
import { ScanSQLInjectionResult } from '../dto/SQLInjection.dto';

interface AuthConfig {
  type: 'none' | 'cookie' | 'header';
  cookies?: Record<string, string>;
  headers?: Record<string, string>;
}

interface ScanRequest {
  url: string;
  authConfig?: AuthConfig;
}

@Controller('scan')
export class ScanController {
  constructor(
    private readonly scanService: ScanXSSService,
    private readonly sqliService: ScanSQLiService,
  ) {}

  @Post('xss')
  async scanXSS(@Body() body: ScanRequest): Promise<ScanXSSResult[]> {
    const { url, authConfig } = body;

    if (!url || typeof url !== 'string') {
      throw new BadRequestException('URL is required');
    }

    try {
      new URL(url);
    } catch {
      throw new BadRequestException('Invalid URL format');
    }

    return this.scanService.scanForXSS(url, authConfig);
  }

  @Post('sql')
  async scanSQLi(@Body() body: ScanRequest): Promise<ScanSQLInjectionResult[]> {
    const { url, authConfig } = body;

    if (!url || typeof url !== 'string') {
      throw new BadRequestException('URL is required');
    }

    try {
      new URL(url);
    } catch {
      throw new BadRequestException('Invalid URL format');
    }

    return this.sqliService.scanForSQLi(url, authConfig);
  }
}
