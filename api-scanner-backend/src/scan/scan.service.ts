import { Injectable, Logger } from '@nestjs/common';
import { spawn, ChildProcess } from 'child_process';
import * as path from 'path';
import axios, { AxiosResponse } from 'axios';
import * as cheerio from 'cheerio';
import { ScanXSSResult } from '../dto/XSS.dto';
import { ScanSQLInjectionResult } from '../dto/SQLInjection.dto';
import { ScannerConfig } from '../config/scanner.config';

type ScanMethod =
  | 'static'
  | 'dynamic'
  | 'python'
  | 'form_post'
  | 'form_get'
  | 'url_parameter'
  | 'selenium_dynamic'
  | 'stored';

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
    required?: boolean;
    pattern?: string;
    placeholder?: string;
    maxlength?: number;
  }>;
}

@Injectable()
export class ScanXSSService {
  private readonly logger = new Logger(ScanXSSService.name);

  async scanForXSS(url: string): Promise<ScanXSSResult[]> {
    const results: ScanXSSResult[] = [];

    try {
      // 1. Analyze the page to get the actual parameters and forms
      const pageInfo = await this.analyzePage(url);

      // 2. Perform a static scan based on the actual parameters
      const staticResults = await this.staticXSSCheck(url, pageInfo);
      results.push(...staticResults);

      // 3. Run a Python script scan (passing parameter information)
      const pythonResults = await this.runPythonXSSScanner(url, pageInfo);
      results.push(...pythonResults);

      // 4. Deduplicate results if enabled
      if (ScannerConfig.validation.deduplicateResults) {
        return this.deduplicateXSSResults(results);
      }
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
      // Extract parameters from URL
      const urlObj = new URL(url);
      urlObj.searchParams.forEach((_, key) => {
        urlParams.push(key);
      });

      // Get page content
      const response = await axios.get(url, {
        timeout: ScannerConfig.network.timeout,
        headers: {
          'User-Agent': 'SecurityScanner/1.0',
        },
      });

      // Parse HTML with cheerio
      const $ = cheerio.load(response.data as string);

      // Find all forms
      $('form').each((_, form) => {
        const $form = $(form);
        const formInfo: PageForm = {
          action: $form.attr('action') || '',
          method: ($form.attr('method') || 'GET').toUpperCase(),
          inputs: [],
        };

        // Find all input fields
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

      // Find parameters in links
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
            // Ignore invalid URLs
          }
        }
      });
    } catch (error) {
      this.logger.warn('Page analysis failed:', error);
    }

    // Add DVWA-specific parameters if none found
    if (urlParams.length === 0 && forms.length === 0) {
      if (url.includes('xss')) {
        urlParams.push('name', 'txtName', 'mtxMessage');
      } else if (url.includes('sqli')) {
        urlParams.push('id', 'Submit');
      } else {
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

    // Test URL parameters
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

    // Test forms with improved logic
    for (const form of pageInfo.forms) {
      for (const input of form.inputs) {
        const maxPayloads = Math.min(
          payloads.length,
          ScannerConfig.xss.maxPayloadsPerField,
        );
        for (const payload of payloads.slice(0, maxPayloads)) {
          // Check if stored XSS testing is enabled
          if (ScannerConfig.xss.checkStoredXSS) {
            const result = await this.testStoredXSS(
              url,
              form,
              input.name,
              payload,
            );
            results.push(result);
          } else {
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
    }

    return results;
  }

  private async testSinglePayload(
    testUrl: string,
    payload: string,
    parameter: string,
    method: string,
  ): Promise<ScanXSSResult> {
    try {
      const response = await axios.get(testUrl, {
        timeout: ScannerConfig.network.timeout,
        maxRedirects: 5,
        headers: {
          'User-Agent': 'SecurityScanner/1.0',
        },
        maxContentLength: ScannerConfig.network.maxContentLength,
        maxBodyLength: ScannerConfig.network.maxContentLength,
      });

      const responseData = this.extractStringFromResponse(response);
      const vulnerable = this.detectXSSInResponse(responseData, payload, false);

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
        result.evidence = this.extractEvidence(responseData, payload);
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

      // Fill form data
      form.inputs.forEach((input) => {
        if (input.name === fieldName) {
          formData[input.name] = payload;
        } else {
          formData[input.name] = input.value || 'test';
        }
      });

      let response: AxiosResponse<any>;
      if (form.method === 'POST') {
        response = await axios.post(formUrl, formData, {
          timeout: ScannerConfig.network.timeout,
          headers: {
            'User-Agent': 'SecurityScanner/1.0',
          },
        });
      } else {
        response = await axios.get(formUrl, {
          timeout: ScannerConfig.network.timeout,
          headers: {
            'User-Agent': 'SecurityScanner/1.0',
          },
          params: formData,
        });
      }

      const responseData = this.extractStringFromResponse(response);
      const vulnerable = this.detectXSSInResponse(responseData, payload, false);

      return {
        payload,
        vulnerable,
        method: `form_${form.method.toLowerCase()}` as 'form_get' | 'form_post',
        field: fieldName,
        url: formUrl,
        context: vulnerable
          ? this.extractContext(responseData, payload)
          : undefined,
        confidence: vulnerable ? 85 : 0,
        severity: vulnerable ? 'high' : undefined,
        evidence: vulnerable
          ? this.extractEvidence(responseData, payload)
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

  private async testStoredXSS(
    baseUrl: string,
    form: PageForm,
    fieldName: string,
    payload: string,
  ): Promise<ScanXSSResult> {
    try {
      const formUrl = this.resolveUrl(baseUrl, form.action);
      // Create unique identifier for tracking
      const uniqueId = `XSS_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      const taggedPayload = payload.replace('XSS', uniqueId);

      const formData: Record<string, string> = {};
      form.inputs.forEach((input) => {
        if (input.name === fieldName) {
          formData[input.name] = taggedPayload;
        } else {
          formData[input.name] = input.value || 'test';
        }
      });

      // 1. Submit payload
      let submitResponse: AxiosResponse<any>;
      if (form.method === 'POST') {
        submitResponse = await axios.post(formUrl, formData, {
          timeout: ScannerConfig.network.timeout,
          headers: {
            'User-Agent': 'SecurityScanner/1.0',
          },
        });
      } else {
        submitResponse = await axios.get(formUrl, {
          timeout: ScannerConfig.network.timeout,
          headers: {
            'User-Agent': 'SecurityScanner/1.0',
          },
          params: formData,
        });
      }

      // 2. Check immediate response (reflected XSS)
      const submitResponseData = this.extractStringFromResponse(submitResponse);
      let vulnerable = this.detectXSSInResponse(
        submitResponseData,
        taggedPayload,
        false,
      );

      let detectionMethod: ScanMethod = 'form_post';

      // 3. If not reflected, check for stored XSS
      if (!vulnerable && ScannerConfig.xss.checkStoredXSS) {
        await new Promise((resolve) =>
          setTimeout(resolve, ScannerConfig.xss.storageCheckDelay),
        );

        // Re-visit the page
        const viewResponse = await axios.get(baseUrl, {
          timeout: ScannerConfig.network.timeout,
          headers: {
            'User-Agent': 'SecurityScanner/1.0',
          },
        });
        const viewResponseData = this.extractStringFromResponse(viewResponse);
        vulnerable = this.detectXSSInResponse(
          viewResponseData,
          taggedPayload,
          true,
        );

        if (vulnerable) {
          detectionMethod = 'stored';
        }

        // Check other common display pages
        if (!vulnerable) {
          for (const page of ScannerConfig.xss.storedXSSPages) {
            try {
              const pageUrl = new URL(page, baseUrl).toString();
              const pageResponse = await axios.get(pageUrl, {
                timeout: ScannerConfig.network.timeout,
                headers: {
                  'User-Agent': 'SecurityScanner/1.0',
                },
              });
              const pageData = this.extractStringFromResponse(pageResponse);
              if (pageData.includes(uniqueId)) {
                vulnerable = true;
                detectionMethod = 'stored';
                break;
              }
            } catch {
              // Ignore pages that don't exist
            }
          }
        }
      }

      return {
        payload: taggedPayload,
        vulnerable,
        method: detectionMethod,
        field: fieldName,
        url: formUrl,
        confidence: vulnerable ? 85 : 0,
        severity: vulnerable
          ? detectionMethod === 'stored'
            ? 'critical'
            : 'high'
          : undefined,
        evidence: vulnerable
          ? `Unique ID ${uniqueId} found in response`
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

  private detectXSSInResponse(
    responseData: string,
    payload: string,
    isStored: boolean = false,
  ): boolean {
    // 1. Check if payload exists in safe contexts
    if (ScannerConfig.validation.excludeSafeContexts) {
      const payloadIndex = responseData.indexOf(payload);
      if (payloadIndex === -1 && !isStored) {
        return false;
      }

      // Check if in safe context
      for (const contextPattern of ScannerConfig.safeContextPatterns) {
        const matches = Array.from(responseData.matchAll(contextPattern));
        for (const match of matches) {
          const matchIndex = match.index;
          if (
            matchIndex !== undefined &&
            matchIndex <= payloadIndex &&
            payloadIndex <= matchIndex + match[0].length
          ) {
            return false; // In safe context, not vulnerable
          }
        }
      }
    }

    // 2. Check if properly encoded
    if (ScannerConfig.xss.encodingCheck) {
      const encodedPayload = this.htmlEncode(payload);
      if (
        responseData.includes(encodedPayload) &&
        !responseData.includes(payload)
      ) {
        return false; // Properly encoded, safe
      }
    }

    // 3. Direct payload match
    if (responseData.includes(payload)) {
      return true;
    }

    // 4. Check for dangerous patterns with context
    const contextualPatterns = [
      {
        pattern: /<script[^>]*>.*?alert\s*\([^)]*\).*?<\/script>/i,
        context: 'script',
        requiresXSS: true,
      },
      {
        pattern: /on\w+\s*=\s*["'].*?alert\s*\([^)]*\).*?["']/i,
        context: 'event_handler',
        requiresXSS: true,
      },
      {
        pattern: /javascript:\s*alert\s*\(/i,
        context: 'javascript_protocol',
        requiresXSS: true,
      },
    ];

    for (const { pattern, requiresXSS } of contextualPatterns) {
      const match = responseData.match(pattern);
      if (match) {
        // Verify it's our injection
        if (requiresXSS && !match[0].includes('XSS')) {
          continue;
        }
        return true;
      }
    }

    return false;
  }

  private htmlEncode(str: string): string {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/\//g, '&#x2F;');
  }

  private extractEvidence(responseData: string, payload: string): string {
    const index = responseData.indexOf(payload);
    if (index === -1)
      return 'Payload not found directly but dangerous pattern detected';

    const start = Math.max(0, index - 30);
    const end = Math.min(responseData.length, index + payload.length + 30);
    return `...${responseData.substring(start, end)}...`;
  }

  private deduplicateXSSResults(results: ScanXSSResult[]): ScanXSSResult[] {
    const seen = new Map<string, ScanXSSResult>();

    for (const result of results) {
      // Create unique key for deduplication
      const key = `${result.parameter || result.field}_${result.vulnerable}_${result.method}`;

      if (!seen.has(key)) {
        seen.set(key, result);
      } else {
        const existing = seen.get(key);
        if (!existing) continue;
        // Keep result with higher confidence
        if ((result.confidence || 0) > (existing.confidence || 0)) {
          seen.set(key, result);
        }
      }
    }

    return Array.from(seen.values());
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
        process.cwd(),
        'src/scripts',
        'xss_scanner.py',
      );

      // Pass parameter information to Python script
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

  private extractContext(responseData: string, payload: string): string {
    const index = responseData.indexOf(payload);
    if (index === -1) return '';

    const start = Math.max(0, index - 50);
    const end = Math.min(responseData.length, index + payload.length + 50);
    return responseData.substring(start, end);
  }

  private extractStringFromResponse(response: AxiosResponse<any>): string {
    const responseData: unknown = response.data;

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

// SQL Injection Service with improvements
@Injectable()
export class ScanSQLiService {
  private readonly logger = new Logger(ScanSQLiService.name);

  async scanForSQLi(url: string): Promise<ScanSQLInjectionResult[]> {
    const results: ScanSQLInjectionResult[] = [];

    try {
      // 1. Analyze page to get actual parameters
      const pageInfo = await this.analyzePage(url);

      // 2. Time-based blind injection detection with baseline
      const timeBasedResults = await this.timeBasedSQLiCheck(url, pageInfo);
      results.push(...timeBasedResults);

      // 3. Error-based detection with improved patterns
      const errorBasedResults = await this.errorBasedSQLiCheck(url, pageInfo);
      results.push(...errorBasedResults);

      // 4. Python sqlmap script
      const pythonResults = await this.runPythonSQLScanner(url, pageInfo);
      results.push(...pythonResults);

      // 5. Deduplicate results if enabled
      if (ScannerConfig.validation.deduplicateResults) {
        return this.deduplicateSQLResults(results);
      }
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
      // Extract parameters from URL
      const urlObj = new URL(url);
      urlObj.searchParams.forEach((_, key) => {
        urlParams.push(key);
      });

      // Get page content
      const response = await axios.get(url, {
        timeout: ScannerConfig.network.timeout,
        headers: {
          'User-Agent': 'SecurityScanner/1.0',
        },
      });

      // Parse HTML with cheerio
      const $ = cheerio.load(response.data as string);

      // Find all forms
      $('form').each((_, form) => {
        const $form = $(form);
        const formInfo: PageForm = {
          action: $form.attr('action') || '',
          method: ($form.attr('method') || 'GET').toUpperCase(),
          inputs: [],
        };

        // Find all input fields
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

    // Add DVWA-specific parameters if none found
    if (urlParams.length === 0 && forms.length === 0) {
      if (url.includes('sqli')) {
        urlParams.push('id', 'Submit');
      } else if (url.includes('xss')) {
        urlParams.push('name', 'txtName');
      } else {
        // Common SQL injection parameters
        urlParams.push('id', 'user_id', 'product_id', 'page', 'category');
      }
    }

    return { urlParams, forms };
  }

  private async timeBasedSQLiCheck(
    url: string,
    pageInfo: { urlParams: string[]; forms: PageForm[] },
  ): Promise<ScanSQLInjectionResult[]> {
    const results: ScanSQLInjectionResult[] = [];

    // 1. Get baseline response times
    const baselineTimes: number[] = [];
    for (let i = 0; i < ScannerConfig.sql.baselineAttempts; i++) {
      try {
        const startTime = Date.now();
        await axios.get(url, { timeout: ScannerConfig.network.timeout });
        baselineTimes.push(Date.now() - startTime);
        await new Promise((resolve) =>
          setTimeout(resolve, ScannerConfig.sql.baselineDelay),
        );
      } catch (err) {
        this.logger.warn('Baseline request failed:', err);
      }
    }

    if (baselineTimes.length === 0) {
      this.logger.warn(
        'Could not establish baseline for time-based SQLi check',
      );
      return results;
    }

    const avgBaseline =
      baselineTimes.reduce((a, b) => a + b) / baselineTimes.length;
    const maxBaseline = Math.max(...baselineTimes);

    const timeBasedPayloads: string[] = [
      `1' AND SLEEP(5)--`,
      `1" AND SLEEP(5)--`,
      `1; WAITFOR DELAY '00:00:05'--`,
      `1' AND pg_sleep(5)--`,
    ];

    // Test each parameter
    for (const param of pageInfo.urlParams) {
      for (const payload of timeBasedPayloads) {
        const testUrl = this.buildTestUrlWithParam(url, param, payload);

        // Test multiple times to reduce false positives
        const testTimes: number[] = [];
        let successCount = 0;

        for (let i = 0; i < ScannerConfig.sql.testAttempts; i++) {
          try {
            const startTime = Date.now();
            await axios.get(testUrl, {
              timeout: ScannerConfig.network.timeout,
            });
            const responseTime = Date.now() - startTime;
            testTimes.push(responseTime);

            // Response time must be significantly greater than baseline
            if (
              responseTime >
                avgBaseline + ScannerConfig.sql.timeBasedThreshold &&
              responseTime > maxBaseline * 2
            ) {
              successCount++;
            }
          } catch (err) {
            // Timeout also counts as potential vulnerability
            if (err && typeof err === 'object' && 'code' in err) {
              const errorCode = (err as { code?: string }).code;
              if (errorCode === 'ECONNABORTED') {
                successCount++;
                testTimes.push(ScannerConfig.network.timeout);
              }
            }
          }
        }

        // Determine vulnerability based on success rate
        const successRate = successCount / ScannerConfig.sql.testAttempts;
        const vulnerable = successRate >= ScannerConfig.sql.minSuccessRate;
        const avgTestTime =
          testTimes.length > 0
            ? testTimes.reduce((a, b) => a + b, 0) / testTimes.length
            : 0;

        const result: ScanSQLInjectionResult = {
          payload,
          vulnerable,
          method: 'time-based',
          responseTime: Math.round(avgTestTime),
          parameter: param,
          url: testUrl,
        };

        if (vulnerable) {
          result.evidence = `Baseline: ${Math.round(avgBaseline)}ms, Test avg: ${Math.round(avgTestTime)}ms, Success rate: ${successCount}/${ScannerConfig.sql.testAttempts}`;
          result.severity = 'high';
          result.confidence = Math.min(95, Math.round(successRate * 100));
          result.databaseType = this.inferDatabaseFromPayload(payload);
          result.injectionType = 'time-blind';
        }

        results.push(result);
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
      `1' AND '1'='2`,
      `' OR '1'='1`,
    ];

    const results: ScanSQLInjectionResult[] = [];

    // Test each parameter
    for (const param of pageInfo.urlParams) {
      for (const payload of errorPayloads) {
        const testUrl = this.buildTestUrlWithParam(url, param, payload);

        try {
          const response = await axios.get(testUrl, {
            timeout: ScannerConfig.network.timeout,
          });
          const responseData = this.extractStringFromResponse(response);

          // Use improved SQL error detection
          const errorDetection = this.detectSQLError(responseData);
          const vulnerable = errorDetection.isError;

          const result: ScanSQLInjectionResult = {
            payload,
            vulnerable,
            method: 'error-based',
            parameter: param,
            url: testUrl,
          };

          if (vulnerable) {
            result.evidence = errorDetection.evidence;
            result.severity = this.calculateSeverityByPayload(payload);
            result.confidence = errorDetection.confidence || 85;
            result.databaseType = errorDetection.dbType;
            result.injectionType = payload.includes("'") ? 'string' : 'numeric';
            result.recommendation =
              'Use parameterized queries or prepared statements';
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

  private detectSQLError(responseData: string): {
    isError: boolean;
    dbType?: 'mysql' | 'postgresql' | 'mssql' | 'oracle' | 'sqlite' | 'unknown';
    evidence?: string;
    confidence?: number;
  } {
    // Precise error patterns with confidence scores
    const precisePatterns: Array<{
      db: string;
      pattern: RegExp;
      weight: number;
    }> = [
      // MySQL errors
      {
        db: 'mysql',
        pattern: /You have an error in your SQL syntax.*MySQL/i,
        weight: 100,
      },
      {
        db: 'mysql',
        pattern: /Unknown column '[^']*' in 'where clause'/i,
        weight: 95,
      },
      {
        db: 'mysql',
        pattern: /mysql_fetch_array\(\)/i,
        weight: 90,
      },
      {
        db: 'mysql',
        pattern: /supplied argument is not a valid MySQL/i,
        weight: 95,
      },
      // PostgreSQL errors
      {
        db: 'postgresql',
        pattern: /ERROR:\s+syntax error at or near/i,
        weight: 100,
      },
      {
        db: 'postgresql',
        pattern: /pg_query\(\).*failed/i,
        weight: 95,
      },
      {
        db: 'postgresql',
        pattern: /unterminated quoted string/i,
        weight: 90,
      },
      // MSSQL errors
      {
        db: 'mssql',
        pattern: /Unclosed quotation mark after the character string/i,
        weight: 100,
      },
      {
        db: 'mssql',
        pattern: /Microsoft OLE DB Provider for SQL Server/i,
        weight: 95,
      },
      {
        db: 'mssql',
        pattern: /Incorrect syntax near/i,
        weight: 85,
      },
      // Oracle errors
      {
        db: 'oracle',
        pattern: /ORA-\d{5}:/i,
        weight: 100,
      },
      {
        db: 'oracle',
        pattern: /Oracle.*Driver.*SQL/i,
        weight: 95,
      },
      // SQLite errors
      {
        db: 'sqlite',
        pattern: /sqlite_query\(\)/i,
        weight: 95,
      },
      {
        db: 'sqlite',
        pattern: /no such table/i,
        weight: 80,
      },
    ];

    // Check for false positives first
    if (ScannerConfig.validation.checkFalsePositives) {
      for (const fp of ScannerConfig.falsePositivePatterns) {
        if (fp.test(responseData)) {
          return { isError: false };
        }
      }
    }

    // Check precise patterns
    for (const { db, pattern, weight } of precisePatterns) {
      const match = responseData.match(pattern);
      if (match) {
        const dbType = db as
          | 'mysql'
          | 'postgresql'
          | 'mssql'
          | 'oracle'
          | 'sqlite';
        return {
          isError: true,
          dbType: dbType,
          evidence: match[0].substring(0, 200),
          confidence: weight,
        };
      }
    }

    return { isError: false };
  }

  private inferDatabaseFromPayload(
    payload: string,
  ): 'mysql' | 'postgresql' | 'mssql' | 'oracle' | 'sqlite' | 'unknown' {
    if (payload.includes('SLEEP')) return 'mysql';
    if (payload.includes('pg_sleep')) return 'postgresql';
    if (payload.includes('WAITFOR DELAY')) return 'mssql';
    return 'unknown';
  }

  private calculateSeverityByPayload(
    payload: string,
  ): 'low' | 'medium' | 'high' | 'critical' {
    if (payload.toUpperCase().includes('DROP TABLE')) return 'critical';
    if (payload.toUpperCase().includes('UNION')) return 'high';
    if (payload.includes('OR') && payload.includes('1=1')) return 'high';
    if (payload === "'" || payload === '"') return 'medium';
    return 'low';
  }

  private deduplicateSQLResults(
    results: ScanSQLInjectionResult[],
  ): ScanSQLInjectionResult[] {
    const seen = new Map<string, ScanSQLInjectionResult>();

    for (const result of results) {
      // Create unique key for deduplication
      const key = `${result.parameter}_${result.vulnerable}_${result.method}_${result.databaseType || 'unknown'}`;

      if (!seen.has(key)) {
        seen.set(key, result);
      } else {
        const existing = seen.get(key);
        if (!existing) continue;
        // Keep result with higher confidence
        if ((result.confidence || 0) > (existing.confidence || 0)) {
          seen.set(key, result);
        }
      }
    }

    return Array.from(seen.values());
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
        process.cwd(),
        'src/scripts',
        'sql_scanner.py',
      );

      // Pass parameter information to Python script
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

  private extractStringFromResponse(response: AxiosResponse<any>): string {
    const responseData: unknown = response.data;

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
