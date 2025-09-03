import { Injectable } from '@nestjs/common';
import axios from 'axios';
import { ScanXSSResult } from '../dto/XSS.dto';
import { ScanSQLInjectionResult } from '../dto/SQLInjection.dto';

@Injectable()
export class ScanXSSService {
  async scanForXSS(url: string): Promise<ScanXSSResult[]> {
    const payloads: string[] = [
      `<script>alert(1)</script>`,
      `" onmouseover="alert(1)`,
      `<img src=x onerror=alert(1)>`,
    ];

    const results: ScanXSSResult[] = [];

    for (const payload of payloads) {
      try {
        const target = `${url}?q=${encodeURIComponent(payload)}`;
        const res = await axios.get<string>(target, {
          timeout: 5000,
        });
        const vulnerable = res.data.includes(payload);

        results.push({ payload, vulnerable });
      } catch (err: unknown) {
        // TypeScript 默认 err 是 unknown，所以要缩小类型范围
        if (err instanceof Error) {
          results.push({ payload, vulnerable: false, error: err.message });
        } else {
          results.push({ payload, vulnerable: false, error: 'Unknown error' });
        }
      }
    }

    return results;
  }
}

@Injectable()
export class ScanSQLiService {
  async scanForSQLi(url: string): Promise<ScanSQLInjectionResult[]> {
    // 常见的 SQLi payload
    const payloads: string[] = [
      `' OR '1'='1`,
      `" OR "1"="1`,
      `admin' --`,
      `1; DROP TABLE users--`,
    ];

    const results: ScanSQLInjectionResult[] = [];

    for (const payload of payloads) {
      try {
        const target = `${url}?id=${encodeURIComponent(payload)}`;
        const res = await axios.get<string>(target, { timeout: 5000 });

        // 简单检测逻辑：如果返回内容包含典型 SQL 错误信息，则认为可能存在 SQLi
        const errorPatterns = [
          'SQL syntax',
          'mysql_fetch',
          'ORA-00933',
          'syntax error',
          'unclosed quotation mark',
        ];

        const vulnerable = errorPatterns.some((pattern) =>
          res.data.toLowerCase().includes(pattern.toLowerCase()),
        );

        results.push({ payload, vulnerable });
      } catch (err: unknown) {
        if (err instanceof Error) {
          results.push({ payload, vulnerable: false, error: err.message });
        } else {
          results.push({ payload, vulnerable: false, error: 'Unknown error' });
        }
      }
    }

    return results;
  }
}
