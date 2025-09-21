import {
  Controller,
  Post,
  Body,
  BadRequestException,
  Logger,
} from '@nestjs/common';
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
  private readonly logger = new Logger(ScanController.name);

  constructor(
    private readonly scanService: ScanXSSService,
    private readonly sqliService: ScanSQLiService,
  ) {}

  @Post('xss')
  async scanXSS(@Body() body: ScanRequest): Promise<ScanXSSResult[]> {
    const { url, authConfig } = body;

    // 基本输入验证
    if (!url || typeof url !== 'string') {
      throw new BadRequestException('URL is required and must be a string');
    }

    // URL 格式验证
    try {
      new URL(url);
    } catch {
      throw new BadRequestException('Invalid URL format');
    }

    // URL 长度限制
    if (url.length > 2048) {
      throw new BadRequestException('URL too long (max 2048 characters)');
    }

    this.logger.log(`XSS scan requested for: ${url}`);

    try {
      return await this.scanService.scanForXSS(url, authConfig);
    } catch (error) {
      this.logger.error(`XSS scan failed for ${url}:`, error);
      throw new BadRequestException('Scan failed. Please try again.');
    }
  }

  @Post('sql')
  async scanSQLi(@Body() body: ScanRequest): Promise<ScanSQLInjectionResult[]> {
    const { url, authConfig } = body;

    // 基本输入验证
    if (!url || typeof url !== 'string') {
      throw new BadRequestException('URL is required and must be a string');
    }

    // URL 格式验证
    try {
      new URL(url);
    } catch {
      throw new BadRequestException('Invalid URL format');
    }

    // URL 长度限制
    if (url.length > 2048) {
      throw new BadRequestException('URL too long (max 2048 characters)');
    }

    this.logger.log(`SQL injection scan requested for: ${url}`);

    try {
      return await this.sqliService.scanForSQLi(url, authConfig);
    } catch (error) {
      this.logger.error(`SQL injection scan failed for ${url}:`, error);
      throw new BadRequestException('Scan failed. Please try again.');
    }
  }
}
