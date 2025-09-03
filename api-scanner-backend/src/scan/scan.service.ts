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
    // Common SQLi payloads
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

        // Simple detection logic: if the response contains typical SQL error messages, it is considered that SQLi may exist.
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
