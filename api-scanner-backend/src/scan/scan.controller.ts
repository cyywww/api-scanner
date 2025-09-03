import { Controller, Post, Body } from '@nestjs/common';
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
    return this.scanService.scanForXSS(url);
  }

  @Post('sql')
  async scanSQLi(@Body('url') url: string): Promise<ScanSQLInjectionResult[]> {
    return this.sqliService.scanForSQLi(url);
  }
}
