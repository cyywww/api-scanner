// scan.service.ts - 完全无错误版本
import { Injectable, Logger } from '@nestjs/common';
import { spawn, ChildProcess } from 'child_process';
import * as path from 'path';
import axios from 'axios';
import { ScanXSSResult } from '../dto/XSS.dto';
import { ScanSQLInjectionResult } from '../dto/SQLInjection.dto';

// 严格类型定义
interface AxiosRequestConfig {
  timeout: number;
  maxRedirects?: number;
  headers?: Record<string, string>;
}

interface ProcessData {
  output: string;
  errorOutput: string;
}

interface ParsedResult {
  payload: string;
  vulnerable: boolean;
  method?: string;
  error?: string;
}

@Injectable()
export class ScanXSSService {
  private readonly logger = new Logger(ScanXSSService.name);

  async scanForXSS(url: string): Promise<ScanXSSResult[]> {
    const results: ScanXSSResult[] = [];

    // 1. 静态扫描
    const staticResults = await this.staticXSSCheck(url);
    results.push(...staticResults);

    // 2. Python 脚本扫描
    const pythonResults = await this.runPythonXSSScanner(url);
    results.push(...pythonResults);

    return results;
  }

  private async staticXSSCheck(url: string): Promise<ScanXSSResult[]> {
    const payloads: string[] = [
      `<script>alert('XSS')</script>`,
      `javascript:alert('XSS')`,
      `<img src=x onerror=alert('XSS')>`,
      `"><script>alert('XSS')</script>`,
      `'><script>alert('XSS')</script>`,
      `<svg onload=alert('XSS')>`,
    ];

    const results: ScanXSSResult[] = [];

    for (const payload of payloads) {
      const testUrl = this.buildTestUrl(url, payload);
      const config: AxiosRequestConfig = {
        timeout: 10000,
        maxRedirects: 5,
        headers: {
          'User-Agent': 'SecurityScanner/1.0',
        },
      };

      try {
        const response = await axios.get(testUrl, config);
        const responseData = this.extractStringFromResponse(response);
        const vulnerable = this.detectXSSInResponse(responseData, payload);

        const result: ScanXSSResult = {
          payload,
          vulnerable,
          method: 'static',
        };

        if (vulnerable) {
          result.context = this.extractContext(responseData, payload);
        }

        results.push(result);
      } catch (err) {
        const errorResult: ScanXSSResult = {
          payload,
          vulnerable: false,
          method: 'static',
          error: this.extractErrorMessage(err),
        };
        results.push(errorResult);
      }
    }

    return results;
  }

  private async runPythonXSSScanner(url: string): Promise<ScanXSSResult[]> {
    return new Promise<ScanXSSResult[]>((resolve) => {
      const pythonScriptPath = path.join(
        __dirname,
        '../scripts',
        'xss_scanner.py',
      );
      const pythonProcess: ChildProcess = spawn('python3', [
        pythonScriptPath,
        url,
      ]);

      const processData: ProcessData = {
        output: '',
        errorOutput: '',
      };

      if (pythonProcess.stdout) {
        pythonProcess.stdout.on('data', (data: Buffer) => {
          processData.output += data.toString();
        });
      }

      if (pythonProcess.stderr) {
        pythonProcess.stderr.on('data', (data: Buffer) => {
          processData.errorOutput += data.toString();
        });
      }

      pythonProcess.on('close', (code: number | null) => {
        if (code === 0 && processData.output) {
          const parsedResults = this.parseJsonSafely(processData.output);
          if (parsedResults) {
            const mappedResults = this.mapPythonResults(parsedResults);
            resolve(mappedResults);
            return;
          }
        }
        resolve([]);
      });

      pythonProcess.on('error', () => {
        resolve([]);
      });
    });
  }

  private buildTestUrl(baseUrl: string, payload: string): string {
    const url = new URL(baseUrl);
    const paramNames: string[] = [
      'q',
      'search',
      'query',
      'input',
      'data',
      'test',
    ];
    // 修复：移除不必要的类型断言
    const randomParam =
      paramNames[Math.floor(Math.random() * paramNames.length)];
    url.searchParams.set(randomParam, payload);
    return url.toString();
  }

  private detectXSSInResponse(responseData: string, payload: string): boolean {
    if (responseData.includes(payload)) {
      return true;
    }

    const dangerousPatterns: RegExp[] = [
      /<script[^>]*>/i,
      /javascript:/i,
      /on\w+\s*=/i,
      /<svg[^>]*onload/i,
      /<img[^>]*onerror/i,
    ];

    return dangerousPatterns.some((pattern: RegExp) =>
      pattern.test(responseData),
    );
  }

  private extractContext(responseData: string, payload: string): string {
    const index = responseData.indexOf(payload);
    if (index === -1) {
      return '';
    }

    const start = Math.max(0, index - 50);
    const end = Math.min(responseData.length, index + payload.length + 50);
    return responseData.substring(start, end);
  }

  private extractStringFromResponse(response: { data: unknown }): string {
    const responseData = response.data;

    if (typeof responseData === 'string') {
      return responseData;
    }

    if (responseData === null || responseData === undefined) {
      return '';
    }

    // 修复：安全的对象序列化，避免 [object Object] 警告
    if (typeof responseData === 'object') {
      try {
        return JSON.stringify(responseData);
      } catch {
        return '[object Object]';
      }
    }

    // 修复：安全的基本类型转换
    if (typeof responseData === 'number' || typeof responseData === 'boolean') {
      return String(responseData);
    }

    return '[Unknown Type]';
  }

  private extractErrorMessage(err: unknown): string {
    if (err && typeof err === 'object' && 'message' in err) {
      const errorObj = err as { message: unknown };
      return typeof errorObj.message === 'string'
        ? errorObj.message
        : 'Error occurred';
    }

    if (typeof err === 'string') {
      return err;
    }

    return 'Unknown error';
  }

  private parseJsonSafely(jsonString: string): ParsedResult[] | null {
    try {
      const parsed: unknown = JSON.parse(jsonString);
      if (Array.isArray(parsed)) {
        return parsed.filter((item: unknown): item is ParsedResult => {
          return (
            item !== null &&
            typeof item === 'object' &&
            'payload' in item &&
            'vulnerable' in item
          );
        });
      }
    } catch {
      return null;
    }
    return null;
  }

  private mapPythonResults(parsedResults: ParsedResult[]): ScanXSSResult[] {
    return parsedResults.map((result: ParsedResult): ScanXSSResult => {
      const mappedResult: ScanXSSResult = {
        payload: String(result.payload),
        vulnerable: Boolean(result.vulnerable),
        method: 'python',
      };

      if (result.error) {
        mappedResult.error = String(result.error);
      }

      return mappedResult;
    });
  }
}

@Injectable()
export class ScanSQLiService {
  private readonly logger = new Logger(ScanSQLiService.name);

  async scanForSQLi(url: string): Promise<ScanSQLInjectionResult[]> {
    const results: ScanSQLInjectionResult[] = [];

    // 1. 基于时间的盲注检测
    const timeBasedResults = await this.timeBasedSQLiCheck(url);
    results.push(...timeBasedResults);

    // 2. 错误信息检测
    const errorBasedResults = await this.errorBasedSQLiCheck(url);
    results.push(...errorBasedResults);

    // 3. Python sqlmap 脚本
    const pythonResults = await this.runPythonSQLScanner(url);
    results.push(...pythonResults);

    return results;
  }

  private async timeBasedSQLiCheck(
    url: string,
  ): Promise<ScanSQLInjectionResult[]> {
    const timeBasedPayloads: string[] = [
      `1' AND SLEEP(5)--`,
      `1" AND SLEEP(5)--`,
      `1; WAITFOR DELAY '00:00:05'--`,
      `1' AND pg_sleep(5)--`,
    ];

    const results: ScanSQLInjectionResult[] = [];

    for (const payload of timeBasedPayloads) {
      const testUrl = this.buildTestUrl(url, payload);

      try {
        const startTime = Date.now();
        await axios.get(testUrl, { timeout: 10000 });
        const responseTime = Date.now() - startTime;
        const vulnerable = responseTime > 4000;

        const result: ScanSQLInjectionResult = {
          payload,
          vulnerable,
          method: 'time-based',
          responseTime,
        };

        if (vulnerable) {
          result.evidence = `Response time: ${responseTime}ms`;
        }

        results.push(result);
      } catch (err) {
        const errorResult: ScanSQLInjectionResult = {
          payload,
          vulnerable: false,
          method: 'time-based',
          error: this.extractErrorMessage(err),
        };
        results.push(errorResult);
      }
    }

    return results;
  }

  private async errorBasedSQLiCheck(
    url: string,
  ): Promise<ScanSQLInjectionResult[]> {
    const errorPayloads: string[] = [
      `'`,
      `"`,
      `'; --`,
      `" OR 1=1--`,
      `' UNION SELECT NULL--`,
    ];

    const results: ScanSQLInjectionResult[] = [];
    const errorPatterns: RegExp[] = [
      /mysql_fetch_array\(\)/i,
      /you have an error in your sql syntax/i,
      /mysql_num_rows\(\)/i,
      /postgresql query failed/i,
      /invalid input syntax/i,
      /microsoft ole db provider for sql server/i,
      /unclosed quotation mark after the character string/i,
      /ora-\d{5}/i,
      /sql syntax.*mysql/i,
      /sql.*error/i,
      /database error/i,
    ];

    for (const payload of errorPayloads) {
      const testUrl = this.buildTestUrl(url, payload);

      try {
        const response = await axios.get(testUrl, { timeout: 8000 });
        const responseData = this.extractStringFromResponse(response);
        const vulnerable = errorPatterns.some((pattern: RegExp) =>
          pattern.test(responseData),
        );

        const result: ScanSQLInjectionResult = {
          payload,
          vulnerable,
          method: 'error-based',
        };

        if (vulnerable) {
          result.evidence = this.extractSQLError(responseData, errorPatterns);
        }

        results.push(result);
      } catch (err) {
        const errorResult: ScanSQLInjectionResult = {
          payload,
          vulnerable: false,
          method: 'error-based',
          error: this.extractErrorMessage(err),
        };
        results.push(errorResult);
      }
    }

    return results;
  }

  private async runPythonSQLScanner(
    url: string,
  ): Promise<ScanSQLInjectionResult[]> {
    return new Promise<ScanSQLInjectionResult[]>((resolve) => {
      const pythonScriptPath = path.join(
        __dirname,
        '../scripts',
        'sql_scanner.py',
      );
      const pythonProcess: ChildProcess = spawn('python3', [
        pythonScriptPath,
        url,
      ]);

      const processData: ProcessData = {
        output: '',
        errorOutput: '',
      };

      if (pythonProcess.stdout) {
        pythonProcess.stdout.on('data', (data: Buffer) => {
          processData.output += data.toString();
        });
      }

      if (pythonProcess.stderr) {
        pythonProcess.stderr.on('data', (data: Buffer) => {
          processData.errorOutput += data.toString();
        });
      }

      pythonProcess.on('close', (code: number | null) => {
        if (code === 0 && processData.output) {
          const parsedResults = this.parseJsonSafely(processData.output);
          if (parsedResults) {
            const mappedResults = this.mapPythonSQLResults(parsedResults);
            resolve(mappedResults);
            return;
          }
        }
        resolve([]);
      });

      pythonProcess.on('error', () => {
        resolve([]);
      });
    });
  }

  private buildTestUrl(baseUrl: string, payload: string): string {
    const url = new URL(baseUrl);
    const paramNames: string[] = [
      'id',
      'user_id',
      'product_id',
      'page',
      'category',
      'item',
    ];
    // 修复：移除不必要的类型断言
    const randomParam =
      paramNames[Math.floor(Math.random() * paramNames.length)];
    url.searchParams.set(randomParam, payload);
    return url.toString();
  }

  private extractSQLError(responseData: string, patterns: RegExp[]): string {
    for (const pattern of patterns) {
      const match = responseData.match(pattern);
      if (match) {
        return match[0];
      }
    }
    return '';
  }

  private extractStringFromResponse(response: { data: unknown }): string {
    const responseData = response.data;

    if (typeof responseData === 'string') {
      return responseData;
    }

    if (responseData === null || responseData === undefined) {
      return '';
    }

    // 修复：安全的对象序列化，避免 [object Object] 警告
    if (typeof responseData === 'object') {
      try {
        return JSON.stringify(responseData);
      } catch {
        return '[object Object]';
      }
    }

    if (typeof responseData === 'number' || typeof responseData === 'boolean') {
      return String(responseData); // ✅ 只对安全类型调用
    }
    return '[Unknown Type]'; // ✅ 其他情况返回明确的字符串
  }

  private extractErrorMessage(err: unknown): string {
    if (err && typeof err === 'object' && 'message' in err) {
      const errorObj = err as { message: unknown };
      return typeof errorObj.message === 'string'
        ? errorObj.message
        : 'Error occurred';
    }

    if (typeof err === 'string') {
      return err;
    }

    return 'Unknown error';
  }

  private parseJsonSafely(jsonString: string): ParsedResult[] | null {
    try {
      const parsed: unknown = JSON.parse(jsonString);
      if (Array.isArray(parsed)) {
        return parsed.filter((item: unknown): item is ParsedResult => {
          return (
            item !== null &&
            typeof item === 'object' &&
            'payload' in item &&
            'vulnerable' in item
          );
        });
      }
    } catch {
      return null;
    }
    return null;
  }

  private mapPythonSQLResults(
    parsedResults: ParsedResult[],
  ): ScanSQLInjectionResult[] {
    return parsedResults.map((result: ParsedResult): ScanSQLInjectionResult => {
      const mappedResult: ScanSQLInjectionResult = {
        payload: String(result.payload),
        vulnerable: Boolean(result.vulnerable),
        method: 'python-sqlmap',
      };

      if (result.error) {
        mappedResult.error = String(result.error);
      }

      return mappedResult;
    });
  }
}
