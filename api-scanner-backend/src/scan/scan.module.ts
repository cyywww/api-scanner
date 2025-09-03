import { Module } from '@nestjs/common';
import { ScanController } from './scan.controller';
import { ScanXSSService, ScanSQLiService } from './scan.service';

@Module({
  controllers: [ScanController],
  providers: [ScanXSSService, ScanSQLiService],
})
export class ScanModule {}
