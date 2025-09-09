// scan.service.ts - 改进版本
import { Injectable, Logger } from '@nestjs/common';
import { spawn, ChildProcess } from 'child_process';
import * as path from 'path';
import axios from 'axios';
import * as cheerio from 'cheerio';
import { ScanXSSResult } from '../dto/XSS.dto';
import { ScanSQLInjectionResult } from '../dto/SQLInjection.dto';

type ScanMethod =
  | 'static'
  | 'dynamic'
  | 'python'
  | 'form_post'
  | 'form_get'
  | 'url_parameter'
  | 'selenium_dynamic';

interface AxiosRequestConfig {
  timeout: number;
  maxRedirects?: number;
  headers?: Record<string, string>;
  maxContentLength?: number;
  maxBodyLength?: number;
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

interface PageForm {
  action: string;
  method: string;
  inputs: Array<{
    name: string;
    type: string;
    value?: string;
  }>;
}

@Injectable()
export class ScanXSSService {
  private readonly logger = new Logger(ScanXSSService.name);

  async scanForXSS(url: string): Promise<ScanXSSResult[]> {
    const results: ScanXSSResult[] = [];

    try {
      // 1. 分析页面，获取实际的参数和表单
      const pageInfo = await this.analyzePage(url);

      // 2. 基于实际参数的静态扫描
      const staticResults = await this.staticXSSCheck(url, pageInfo);
      results.push(...staticResults);

      // 3. Python 脚本扫描（传递参数信息）
      const pythonResults = await this.runPythonXSSScanner(url, pageInfo);
      results.push(...pythonResults);
    } catch (error) {
      this.logger.error('XSS scan failed:', error);
    }

    return results;
  }

  private async analyzePage(url: string): Promise<{
    urlParams: string[];
    forms: PageForm[];
  }> {
    const urlParams: string[] = [];
    const forms: PageForm[] = [];

    try {
      // 从URL中提取参数
      const urlObj = new URL(url);
      urlObj.searchParams.forEach((_, key) => {
        urlParams.push(key);
      });

      // 获取页面内容
      const response = await axios.get(url, {
        timeout: 10000,
        headers: {
          'User-Agent': 'SecurityScanner/1.0',
        },
      });

      // 使用 cheerio 解析HTML
      const $ = cheerio.load(response.data as string);

      // 查找所有表单
      $('form').each((_, form) => {
        const $form = $(form);
        const formInfo: PageForm = {
          action: $form.attr('action') || '',
          method: ($form.attr('method') || 'GET').toUpperCase(),
          inputs: [],
        };

        // 查找所有输入字段
        $form.find('input, textarea, select').each((_, input) => {
          const $input = $(input);
          const name = $input.attr('name');
          const type = $input.attr('type') || 'text';

          if (name && type !== 'submit' && type !== 'button') {
            formInfo.inputs.push({
              name,
              type,
              value: $input.attr('value'),
            });
          }
        });

        if (formInfo.inputs.length > 0) {
          forms.push(formInfo);
        }
      });

      // 查找URL中的链接，提取参数名
      $('a[href]').each((_, link) => {
        const href = $(link).attr('href');
        if (href && href.includes('?')) {
          try {
            const linkUrl = new URL(href, url);
            linkUrl.searchParams.forEach((_, key) => {
              if (!urlParams.includes(key)) {
                urlParams.push(key);
              }
            });
          } catch {
            // Ignore invalid URLs in href attributes
          }
        }
      });
    } catch (error) {
      this.logger.warn('Page analysis failed:', error);
    }

    // 如果没有找到参数，添加DVWA常用参数
    if (urlParams.length === 0 && forms.length === 0) {
      // DVWA 特定参数
      if (url.includes('xss')) {
        urlParams.push('name', 'txtName', 'mtxMessage');
      } else if (url.includes('sqli')) {
        urlParams.push('id', 'Submit');
      } else {
        // 通用参数
        urlParams.push('q', 'search', 'query', 'input', 'data');
      }
    }

    return { urlParams, forms };
  }

  private async staticXSSCheck(
    url: string,
    pageInfo: { urlParams: string[]; forms: PageForm[] },
  ): Promise<ScanXSSResult[]> {
    const payloads: string[] = [
      `<script>alert('XSS')</script>`,
      `javascript:alert('XSS')`,
      `<img src=x onerror=alert('XSS')>`,
      `"><script>alert('XSS')</script>`,
      `'><script>alert('XSS')</script>`,
      `<svg onload=alert('XSS')>`,
    ];

    const results: ScanXSSResult[] = [];

    // 测试URL参数
    for (const param of pageInfo.urlParams) {
      for (const payload of payloads) {
        const testUrl = this.buildTestUrlWithParam(url, param, payload);
        const result = await this.testSinglePayload(
          testUrl,
          payload,
          param,
          'url_parameter',
        );
        results.push(result);
      }
    }

    // 测试表单
    for (const form of pageInfo.forms) {
      for (const input of form.inputs) {
        for (const payload of payloads.slice(0, 3)) {
          // 限制表单测试数量
          const result = await this.testFormPayload(
            url,
            form,
            input.name,
            payload,
          );
          results.push(result);
        }
      }
    }

    return results;
  }

  private async testSinglePayload(
    testUrl: string,
    payload: string,
    parameter: string,
    method: string,
  ): Promise<ScanXSSResult> {
    const config: AxiosRequestConfig = {
      timeout: 10000,
      maxRedirects: 5,
      headers: {
        'User-Agent': 'SecurityScanner/1.0',
      },
      maxContentLength: 50 * 1024 * 1024, // 50MB
      maxBodyLength: 50 * 1024 * 1024,
    };

    try {
      const response = await axios.get(testUrl, config);
      const responseData = this.extractStringFromResponse(response);
      const vulnerable = this.detectXSSInResponse(responseData, payload);

      const result: ScanXSSResult = {
        payload,
        vulnerable,
        method: method as ScanMethod,
        parameter,
        url: testUrl,
      };

      if (vulnerable) {
        result.context = this.extractContext(responseData, payload);
        result.confidence = 90;
        result.severity = 'high';
      }

      return result;
    } catch (err) {
      return {
        payload,
        vulnerable: false,
        method: method as ScanMethod,
        parameter,
        error: this.extractErrorMessage(err),
      };
    }
  }

  private async testFormPayload(
    baseUrl: string,
    form: PageForm,
    fieldName: string,
    payload: string,
  ): Promise<ScanXSSResult> {
    try {
      const formUrl = this.resolveUrl(baseUrl, form.action);
      const formData: Record<string, string> = {};

      // 填充表单数据
      form.inputs.forEach((input) => {
        if (input.name === fieldName) {
          formData[input.name] = payload;
        } else {
          formData[input.name] = input.value || 'test';
        }
      });

      const config: AxiosRequestConfig = {
        timeout: 10000,
        headers: {
          'User-Agent': 'SecurityScanner/1.0',
        },
      };

      let response;
      if (form.method === 'POST') {
        response = await axios.post(formUrl, formData, config);
      } else {
        response = await axios.get(formUrl, { ...config, params: formData });
      }

      const responseData = this.extractStringFromResponse(response);
      const vulnerable = this.detectXSSInResponse(responseData, payload);

      return {
        payload,
        vulnerable,
        method: `form_${form.method.toLowerCase()}` as 'form_get' | 'form_post',
        field: fieldName,
        url: formUrl,
        context: vulnerable
          ? this.extractContext(responseData, payload)
          : undefined,
      };
    } catch (err) {
      return {
        payload,
        vulnerable: false,
        method: 'form_post',
        field: fieldName,
        error: this.extractErrorMessage(err),
      };
    }
  }

  private buildTestUrlWithParam(
    baseUrl: string,
    param: string,
    payload: string,
  ): string {
    const url = new URL(baseUrl);
    url.searchParams.set(param, payload);
    return url.toString();
  }

  private resolveUrl(baseUrl: string, relativeUrl: string): string {
    if (!relativeUrl) return baseUrl;
    if (relativeUrl.startsWith('http')) return relativeUrl;

    const base = new URL(baseUrl);
    if (relativeUrl.startsWith('/')) {
      return `${base.protocol}//${base.host}${relativeUrl}`;
    }

    const basePath = base.pathname.substring(
      0,
      base.pathname.lastIndexOf('/') + 1,
    );
    return `${base.protocol}//${base.host}${basePath}${relativeUrl}`;
  }

  private async runPythonXSSScanner(
    url: string,
    pageInfo: { urlParams: string[]; forms: PageForm[] },
  ): Promise<ScanXSSResult[]> {
    return new Promise<ScanXSSResult[]>((resolve) => {
      const pythonScriptPath = path.join(
        __dirname,
        '../scripts',
        'xss_scanner.py',
      );

      // 传递参数信息给Python脚本
      const args = [pythonScriptPath, url];
      if (pageInfo.urlParams.length > 0) {
        args.push('--params', pageInfo.urlParams.join(','));
      }

      const pythonProcess: ChildProcess = spawn('python3', args);

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

  // ... 其他辅助方法保持不变 ...

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
    if (index === -1) return '';

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

    if (typeof responseData === 'object') {
      try {
        return JSON.stringify(responseData);
      } catch {
        return '[object Object]';
      }
    }

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

// SQLi服务类似改进...
@Injectable()
export class ScanSQLiService {
  private readonly logger = new Logger(ScanSQLiService.name);

  async scanForSQLi(url: string): Promise<ScanSQLInjectionResult[]> {
    const results: ScanSQLInjectionResult[] = [];

    try {
      // 1. 分析页面，获取实际的参数
      const pageInfo = await this.analyzePage(url);

      // 2. 基于时间的盲注检测
      const timeBasedResults = await this.timeBasedSQLiCheck(url, pageInfo);
      results.push(...timeBasedResults);

      // 3. 错误信息检测
      const errorBasedResults = await this.errorBasedSQLiCheck(url, pageInfo);
      results.push(...errorBasedResults);

      // 4. Python sqlmap 脚本
      const pythonResults = await this.runPythonSQLScanner(url, pageInfo);
      results.push(...pythonResults);
    } catch (error) {
      this.logger.error('SQLi scan failed:', error);
    }

    return results;
  }

  private async analyzePage(url: string): Promise<{
    urlParams: string[];
    forms: PageForm[];
  }> {
    const urlParams: string[] = [];
    const forms: PageForm[] = [];

    try {
      // 从URL中提取参数
      const urlObj = new URL(url);
      urlObj.searchParams.forEach((_, key) => {
        urlParams.push(key);
      });

      // 获取页面内容
      const response = await axios.get(url, {
        timeout: 10000,
        headers: {
          'User-Agent': 'SecurityScanner/1.0',
        },
      });

      // 使用 cheerio 解析HTML
      const $ = cheerio.load(response.data as string);

      // 查找所有表单
      $('form').each((_, form) => {
        const $form = $(form);
        const formInfo: PageForm = {
          action: $form.attr('action') || '',
          method: ($form.attr('method') || 'GET').toUpperCase(),
          inputs: [],
        };

        // 查找所有输入字段
        $form.find('input, textarea, select').each((_, input) => {
          const $input = $(input);
          const name = $input.attr('name');
          const type = $input.attr('type') || 'text';

          if (name && type !== 'submit' && type !== 'button') {
            formInfo.inputs.push({
              name,
              type,
              value: $input.attr('value'),
            });
          }
        });

        if (formInfo.inputs.length > 0) {
          forms.push(formInfo);
        }
      });
    } catch (error) {
      this.logger.warn('Page analysis failed:', error);
    }

    // 如果没有找到参数，添加DVWA常用参数
    if (urlParams.length === 0 && forms.length === 0) {
      if (url.includes('sqli')) {
        urlParams.push('id', 'Submit');
      } else if (url.includes('xss')) {
        urlParams.push('name', 'txtName');
      } else {
        // SQL注入常用参数
        urlParams.push('id', 'user_id', 'product_id', 'page', 'category');
      }
    }

    return { urlParams, forms };
  }

  private async timeBasedSQLiCheck(
    url: string,
    pageInfo: { urlParams: string[]; forms: PageForm[] },
  ): Promise<ScanSQLInjectionResult[]> {
    const timeBasedPayloads: string[] = [
      `1' AND SLEEP(5)--`,
      `1" AND SLEEP(5)--`,
      `1; WAITFOR DELAY '00:00:05'--`,
      `1' AND pg_sleep(5)--`,
    ];

    const results: ScanSQLInjectionResult[] = [];

    // 测试每个参数
    for (const param of pageInfo.urlParams) {
      for (const payload of timeBasedPayloads) {
        const testUrl = this.buildTestUrlWithParam(url, param, payload);

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
            parameter: param,
            url: testUrl,
          };

          if (vulnerable) {
            result.evidence = `Response time: ${responseTime}ms`;
            result.severity = 'high';
            result.confidence = 85;
          }

          results.push(result);
        } catch (err) {
          const errorResult: ScanSQLInjectionResult = {
            payload,
            vulnerable: false,
            method: 'time-based',
            parameter: param,
            error: this.extractErrorMessage(err),
          };
          results.push(errorResult);
        }
      }
    }

    return results;
  }

  private async errorBasedSQLiCheck(
    url: string,
    pageInfo: { urlParams: string[]; forms: PageForm[] },
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

    // 测试每个参数
    for (const param of pageInfo.urlParams) {
      for (const payload of errorPayloads) {
        const testUrl = this.buildTestUrlWithParam(url, param, payload);

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
            parameter: param,
            url: testUrl,
          };

          if (vulnerable) {
            result.evidence = this.extractSQLError(responseData, errorPatterns);
            result.severity = 'critical';
            result.confidence = 95;
          }

          results.push(result);
        } catch (err) {
          const errorResult: ScanSQLInjectionResult = {
            payload,
            vulnerable: false,
            method: 'error-based',
            parameter: param,
            error: this.extractErrorMessage(err),
          };
          results.push(errorResult);
        }
      }
    }

    return results;
  }

  private buildTestUrlWithParam(
    baseUrl: string,
    param: string,
    payload: string,
  ): string {
    const url = new URL(baseUrl);
    url.searchParams.set(param, payload);
    return url.toString();
  }

  private async runPythonSQLScanner(
    url: string,
    pageInfo: { urlParams: string[]; forms: PageForm[] },
  ): Promise<ScanSQLInjectionResult[]> {
    return new Promise<ScanSQLInjectionResult[]>((resolve) => {
      const pythonScriptPath = path.join(
        __dirname,
        '../scripts',
        'sql_scanner.py',
      );

      // 传递参数信息给Python脚本
      const args = [pythonScriptPath, url];
      if (pageInfo.urlParams.length > 0) {
        args.push('--params', pageInfo.urlParams.join(','));
      }

      const pythonProcess: ChildProcess = spawn('python3', args);

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

  // ... 其他辅助方法保持不变 ...

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

    if (typeof responseData === 'object') {
      try {
        return JSON.stringify(responseData);
      } catch {
        return '[object Object]';
      }
    }

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
