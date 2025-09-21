import { Injectable, Logger } from '@nestjs/common';
import { spawn, ChildProcess } from 'child_process';
import * as path from 'path';
import axios, { AxiosResponse, AxiosRequestConfig } from 'axios';
import * as cheerio from 'cheerio';
import { ScanXSSResult } from '../dto/XSS.dto';
import { ScanSQLInjectionResult } from '../dto/SQLInjection.dto';
import { ScannerConfig } from '../config/scanner.config';
import * as fs from 'fs';

interface AuthConfig {
  type: 'none' | 'cookie' | 'header';
  cookies?: Record<string, string>;
  headers?: Record<string, string>;
}

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
  parameter?: string;
  field?: string;
  url?: string;
  confidence?: number;
  severity?: string;
  evidence?: string;
  databaseType?: string;
  injectionType?: string;
  responseTime?: number;
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

  async scanForXSS(
    url: string,
    authConfig?: AuthConfig,
  ): Promise<ScanXSSResult[]> {
    const results: ScanXSSResult[] = [];

    try {
      this.logger.log(`Starting XSS scan for: ${url}`);

      // 1. Analyze the page to get the actual parameters and forms
      const pageInfo = await this.analyzePage(url, authConfig);
      this.logger.log(
        `Found URL params: ${JSON.stringify(pageInfo.urlParams)}`,
      );
      this.logger.log(`Found ${pageInfo.forms.length} forms`);

      // 2. Perform a static scan based on the actual parameters
      const staticResults = await this.staticXSSCheck(
        url,
        pageInfo,
        authConfig,
      );
      results.push(...staticResults);
      this.logger.log(`Static scan completed: ${staticResults.length} results`);

      // 3. Run a Python script scan (passing parameter information)
      const pythonResults = await this.runPythonXSSScanner(
        url,
        pageInfo,
        authConfig,
      );
      results.push(...pythonResults);
      this.logger.log(`Python scan completed: ${pythonResults.length} results`);

      // 4. Deduplicate results if enabled
      if (ScannerConfig.validation.deduplicateResults) {
        const deduplicatedResults = this.deduplicateXSSResults(results);
        this.logger.log(`Total unique results: ${deduplicatedResults.length}`);
        return deduplicatedResults;
      }
    } catch (error) {
      this.logger.error('XSS scan failed:', error);
    }

    return results;
  }

  private async analyzePage(
    url: string,
    authConfig?: AuthConfig,
  ): Promise<{
    urlParams: string[];
    forms: PageForm[];
  }> {
    const urlParams: string[] = [];
    const forms: PageForm[] = [];

    try {
      // Extract parameters from URL
      const urlObj = new URL(url);
      urlObj.searchParams.forEach((value, key) => {
        urlParams.push(key);
        this.logger.debug(`Found URL param: ${key}=${value}`);
      });

      const requestOptions: AxiosRequestConfig = {
        timeout: ScannerConfig.network.timeout,
        headers: {
          'User-Agent': 'SecurityScanner/1.0',
          Accept:
            'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        },
        validateStatus: () => true, // Accept any status code
      };

      if (authConfig && requestOptions.headers) {
        if (authConfig.type === 'cookie' && authConfig.cookies) {
          requestOptions.headers['Cookie'] = Object.entries(authConfig.cookies)
            .map(([key, value]) => `${key}=${value}`)
            .join('; ');
        } else if (authConfig.type === 'header' && authConfig.headers) {
          Object.assign(requestOptions.headers, authConfig.headers);
        }
      }

      // Get page content
      const response = await axios.get(url, requestOptions);

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
          this.logger.debug(`Found form with ${formInfo.inputs.length} inputs`);
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

    // If no parameters found, don't add defaults - let Python scanner handle it
    if (urlParams.length === 0 && forms.length === 0) {
      this.logger.warn('No parameters or forms found in the page');
    }

    return { urlParams, forms };
  }

  private async staticXSSCheck(
    url: string,
    pageInfo: { urlParams: string[]; forms: PageForm[] },
    authConfig?: AuthConfig,
  ): Promise<ScanXSSResult[]> {
    const payloads: string[] = [
      `<script>alert('XSS')</script>`,
      `javascript:alert('XSS')`,
      `<img src=x onerror=alert('XSS')>`,
      `"><script>alert('XSS')</script>`,
      `'><script>alert('XSS')</script>`,
      `<svg onload=alert('XSS')>`,
      `<body onload=alert('XSS')>`,
      `<iframe src=javascript:alert('XSS')>`,
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
          authConfig,
        );
        results.push(result);

        // Add small delay to avoid overwhelming the server
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
    }

    // Test forms
    for (const form of pageInfo.forms) {
      for (const input of form.inputs) {
        const maxPayloads = Math.min(
          payloads.length,
          ScannerConfig.xss.maxPayloadsPerField,
        );
        for (const payload of payloads.slice(0, maxPayloads)) {
          // Check if stored XSS testing is enabled
          if (ScannerConfig.xss.checkStoredXSS && form.method === 'POST') {
            const result = await this.testStoredXSS(
              url,
              form,
              input.name,
              payload,
              authConfig,
            );
            results.push(result);
          } else {
            const result = await this.testFormPayload(
              url,
              form,
              input.name,
              payload,
              authConfig,
            );
            results.push(result);
          }

          // Add small delay
          await new Promise((resolve) => setTimeout(resolve, 100));
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
    authConfig?: AuthConfig,
  ): Promise<ScanXSSResult> {
    try {
      const requestOptions: AxiosRequestConfig = {
        timeout: ScannerConfig.network.timeout,
        maxRedirects: 5,
        headers: {
          'User-Agent': 'SecurityScanner/1.0',
        },
        maxContentLength: ScannerConfig.network.maxContentLength,
        maxBodyLength: ScannerConfig.network.maxContentLength,
        validateStatus: () => true,
      };

      if (authConfig && requestOptions.headers) {
        if (authConfig.type === 'cookie' && authConfig.cookies) {
          requestOptions.headers['Cookie'] = Object.entries(authConfig.cookies)
            .map(([key, value]) => `${key}=${value}`)
            .join('; ');
        } else if (authConfig.type === 'header' && authConfig.headers) {
          Object.assign(requestOptions.headers, authConfig.headers);
        }
      }

      const response = await axios.get(testUrl, requestOptions);

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
    authConfig?: AuthConfig,
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

      const requestOptions: AxiosRequestConfig = {
        timeout: ScannerConfig.network.timeout,
        headers: {
          'User-Agent': 'SecurityScanner/1.0',
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        validateStatus: () => true,
      };

      if (authConfig && requestOptions.headers) {
        if (authConfig.type === 'cookie' && authConfig.cookies) {
          requestOptions.headers['Cookie'] = Object.entries(authConfig.cookies)
            .map(([key, value]) => `${key}=${value}`)
            .join('; ');
        } else if (authConfig.type === 'header' && authConfig.headers) {
          Object.assign(requestOptions.headers, authConfig.headers);
        }
      }

      let response: AxiosResponse<any>;
      if (form.method === 'POST') {
        response = await axios.post(formUrl, formData, requestOptions);
      } else {
        response = await axios.get(formUrl, {
          ...requestOptions,
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
    authConfig?: AuthConfig,
  ): Promise<ScanXSSResult> {
    try {
      const formUrl = this.resolveUrl(baseUrl, form.action);

      // Create unique identifier for tracking stored XSS
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

      const requestOptions: AxiosRequestConfig = {
        timeout: ScannerConfig.network.timeout,
        headers: {
          'User-Agent': 'SecurityScanner/1.0',
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        validateStatus: () => true,
      };

      if (authConfig && requestOptions.headers) {
        if (authConfig.type === 'cookie' && authConfig.cookies) {
          requestOptions.headers['Cookie'] = Object.entries(authConfig.cookies)
            .map(([key, value]) => `${key}=${value}`)
            .join('; ');
        } else if (authConfig.type === 'header' && authConfig.headers) {
          Object.assign(requestOptions.headers, authConfig.headers);
        }
      }

      // 1. Submit payload
      let submitResponse: AxiosResponse<any>;
      if (form.method === 'POST') {
        submitResponse = await axios.post(formUrl, formData, requestOptions);
      } else {
        submitResponse = await axios.get(formUrl, {
          ...requestOptions,
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

      let detectionMethod: ScanMethod =
        `form_${form.method.toLowerCase()}` as ScanMethod;

      // 3. If not reflected, check for stored XSS
      if (!vulnerable && ScannerConfig.xss.checkStoredXSS) {
        // Wait a bit for the data to be stored
        await new Promise((resolve) =>
          setTimeout(resolve, ScannerConfig.xss.storageCheckDelay),
        );

        const viewRequestOptions: AxiosRequestConfig = {
          timeout: ScannerConfig.network.timeout,
          headers: {
            'User-Agent': 'SecurityScanner/1.0',
          },
          validateStatus: () => true,
        };

        if (authConfig && viewRequestOptions.headers) {
          if (authConfig.type === 'cookie' && authConfig.cookies) {
            viewRequestOptions.headers['Cookie'] = Object.entries(
              authConfig.cookies,
            )
              .map(([key, value]) => `${key}=${value}`)
              .join('; ');
          } else if (authConfig.type === 'header' && authConfig.headers) {
            Object.assign(viewRequestOptions.headers, authConfig.headers);
          }
        }

        // Re-visit the page to check if payload was stored
        const viewResponse = await axios.get(baseUrl, viewRequestOptions);

        const viewResponseData = this.extractStringFromResponse(viewResponse);
        vulnerable = this.detectXSSInResponse(
          viewResponseData,
          taggedPayload,
          true,
        );

        if (vulnerable) {
          detectionMethod = 'stored';
        }

        // Also check other common pages where stored content might appear
        if (!vulnerable) {
          for (const page of ScannerConfig.xss.storedXSSPages) {
            try {
              const pageUrl = new URL(page, baseUrl).toString();
              const pageResponse = await axios.get(pageUrl, viewRequestOptions);
              const pageData = this.extractStringFromResponse(pageResponse);

              // Check with stored XSS detection
              if (this.detectXSSInResponse(pageData, taggedPayload, true)) {
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
        confidence: vulnerable ? (detectionMethod === 'stored' ? 95 : 85) : 0,
        severity: vulnerable
          ? detectionMethod === 'stored'
            ? 'critical' // Stored XSS is more severe
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
    // Check if response is error page
    if (
      responseData.includes('404 Not Found') ||
      responseData.includes('500 Internal Server Error')
    ) {
      return false;
    }

    // For stored XSS, I need to look for a unique identifier
    // rather than the exact payload, as it might be processed
    if (isStored) {
      // Extract unique ID from payload if it exists
      const uniqueIdMatch = payload.match(/XSS_\d+_[a-z0-9]+/i);
      if (uniqueIdMatch) {
        const uniqueId = uniqueIdMatch[0];
        // Check if the unique ID appears anywhere in the response
        if (responseData.includes(uniqueId)) {
          // Make sure it's in an executable context
          if (!this.isInSafeContext(responseData, uniqueId)) {
            return true;
          }
        }
      }

      // Also check for partial matches for stored XSS
      // Sometimes the payload is modified when stored
      const payloadCore = payload.replace(/['"<>]/g, '');
      if (payloadCore && responseData.includes(payloadCore)) {
        // Check if it's in a dangerous context
        const patterns = [
          /<script[^>]*>.*?alert.*?<\/script>/i,
          /on\w+\s*=.*?alert/i,
        ];
        for (const pattern of patterns) {
          if (pattern.test(responseData)) {
            return true;
          }
        }
      }
    }

    // For reflected XSS (immediate response)
    // 1. Direct payload match
    if (responseData.includes(payload)) {
      // Check if it's in a safe context
      if (this.isInSafeContext(responseData, payload)) {
        return false;
      }
      return true;
    }

    // 2. Check for partial matches (payload might be modified)
    const payloadPatterns = [
      payload.replace(/['"]/g, ''), // Without quotes
      payload.replace(/</g, '&lt;').replace(/>/g, '&gt;'), // HTML encoded
      encodeURIComponent(payload), // URL encoded
    ];

    for (const pattern of payloadPatterns) {
      if (responseData.includes(pattern)) {
        // Found encoded version - not vulnerable
        return false;
      }
    }

    // 3. Check for dangerous patterns that might indicate our injection worked
    if (payload.includes('alert') && responseData.includes('alert')) {
      // Check if it's actually executable
      const alertPattern = /<script[^>]*>.*?alert\s*\([^)]*\).*?<\/script>/i;
      if (alertPattern.test(responseData)) {
        return true;
      }
    }

    return false;
  }

  private isInSafeContext(responseData: string, payload: string): boolean {
    const payloadIndex = responseData.indexOf(payload);
    if (payloadIndex === -1) return false;

    // Check if in textarea
    const textareaPattern = /<textarea[^>]*>(.*?)<\/textarea>/gis;
    const textareaMatches = responseData.matchAll(textareaPattern);
    for (const match of textareaMatches) {
      if (
        match.index !== undefined &&
        match.index <= payloadIndex &&
        payloadIndex <= match.index + match[0].length
      ) {
        return true;
      }
    }

    // Check if in comment
    const commentPattern = /<!--.*?-->/gs;
    const commentMatches = responseData.matchAll(commentPattern);
    for (const match of commentMatches) {
      if (
        match.index !== undefined &&
        match.index <= payloadIndex &&
        payloadIndex <= match.index + match[0].length
      ) {
        return true;
      }
    }

    return false;
  }

  private extractEvidence(responseData: string, payload: string): string {
    const index = responseData.indexOf(payload);
    if (index === -1) return 'Payload pattern detected but not directly found';

    const start = Math.max(0, index - 50);
    const end = Math.min(responseData.length, index + payload.length + 50);
    return `...${responseData.substring(start, end).replace(/\s+/g, ' ').trim()}...`;
  }

  private extractContext(responseData: string, payload: string): string {
    const index = responseData.indexOf(payload);
    if (index === -1) return '';

    const start = Math.max(0, index - 100);
    const end = Math.min(responseData.length, index + payload.length + 100);
    return responseData.substring(start, end).replace(/\s+/g, ' ').trim();
  }

  private deduplicateXSSResults(results: ScanXSSResult[]): ScanXSSResult[] {
    const seen = new Map<string, ScanXSSResult>();

    for (const result of results) {
      // Create unique key for deduplication
      const key = `${result.parameter || result.field || 'unknown'}_${result.vulnerable}_${result.method}_${result.payload}`;

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
    try {
      const url = new URL(baseUrl);
      url.searchParams.set(param, payload);
      return url.toString();
    } catch {
      // Fallback for invalid URLs
      const separator = baseUrl.includes('?') ? '&' : '?';
      return `${baseUrl}${separator}${param}=${encodeURIComponent(payload)}`;
    }
  }

  private resolveUrl(baseUrl: string, relativeUrl: string): string {
    if (!relativeUrl) return baseUrl;
    if (relativeUrl.startsWith('http')) return relativeUrl;

    try {
      const base = new URL(baseUrl);
      if (relativeUrl.startsWith('/')) {
        return `${base.protocol}//${base.host}${relativeUrl}`;
      }

      const basePath = base.pathname.substring(
        0,
        base.pathname.lastIndexOf('/') + 1,
      );
      return `${base.protocol}//${base.host}${basePath}${relativeUrl}`;
    } catch {
      return baseUrl;
    }
  }

  private async runPythonXSSScanner(
    url: string,
    pageInfo: { urlParams: string[]; forms: PageForm[] },
    authConfig?: AuthConfig,
  ): Promise<ScanXSSResult[]> {
    return new Promise<ScanXSSResult[]>((resolve) => {
      const pythonScriptPath = path.join(
        __dirname,
        '..',
        'scripts',
        'xss_scanner.py',
      );

      // Check if script exists
      if (!fs.existsSync(pythonScriptPath)) {
        this.logger.error(`Python script not found: ${pythonScriptPath}`);
        resolve([]);
        return;
      }

      // Pass parameter information to Python script
      const args = [pythonScriptPath, url];
      if (pageInfo.urlParams.length > 0) {
        args.push('--params', pageInfo.urlParams.join(','));
      }

      if (authConfig) {
        if (authConfig.type === 'cookie' && authConfig.cookies) {
          const cookieString = Object.entries(authConfig.cookies)
            .map(([key, value]) => `${key}=${value}`)
            .join('; ');
          args.push('--cookies', cookieString);
        } else if (authConfig.type === 'header' && authConfig.headers) {
          args.push('--headers', JSON.stringify(authConfig.headers));
        }
      }

      this.logger.debug(
        `Running Python XSS scanner with args: ${args.join(' ')}`,
      );

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
          this.logger.debug(`Python stderr: ${data.toString()}`);
        });
      }

      pythonProcess.on('close', (code: number | null) => {
        this.logger.debug(`Python process exited with code ${code}`);

        if (code === 0 && processData.output) {
          try {
            const parsedResults = this.parseJsonSafely(processData.output);
            if (parsedResults) {
              const mappedResults = this.mapPythonResults(parsedResults);
              this.logger.debug(
                `Python scan returned ${mappedResults.length} results`,
              );
              resolve(mappedResults);
              return;
            }
          } catch (error) {
            this.logger.error('Failed to parse Python output:', error);
            this.logger.debug('Python output was:', processData.output);
          }
        }

        resolve([]);
      });

      pythonProcess.on('error', (error) => {
        this.logger.error('Failed to run Python scanner:', error);
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
    } catch (error) {
      this.logger.error('JSON parse error:', error);
      return null;
    }
    return null;
  }

  private mapPythonResults(parsedResults: ParsedResult[]): ScanXSSResult[] {
    return parsedResults.map((result: ParsedResult): ScanXSSResult => {
      let method: ScanMethod = 'python';
      if (result.method) {
        const validMethods: ScanMethod[] = [
          'static',
          'dynamic',
          'python',
          'form_post',
          'form_get',
          'url_parameter',
          'selenium_dynamic',
          'stored',
        ];
        if (validMethods.includes(result.method as ScanMethod)) {
          method = result.method as ScanMethod;
        }
      }

      const mappedResult: ScanXSSResult = {
        payload: String(result.payload),
        vulnerable: Boolean(result.vulnerable),
        method: method,
      };

      if (result.parameter) mappedResult.parameter = String(result.parameter);
      if (result.field) mappedResult.field = String(result.field);
      if (result.url) mappedResult.url = String(result.url);
      if (result.confidence)
        mappedResult.confidence = Number(result.confidence);
      if (result.severity) {
        mappedResult.severity = result.severity as
          | 'low'
          | 'medium'
          | 'high'
          | 'critical';
      }
      if (result.evidence) mappedResult.evidence = String(result.evidence);
      if (result.error) mappedResult.error = String(result.error);

      return mappedResult;
    });
  }
}

@Injectable()
export class ScanSQLiService {
  private readonly logger = new Logger(ScanSQLiService.name);

  async scanForSQLi(
    url: string,
    authConfig?: AuthConfig,
  ): Promise<ScanSQLInjectionResult[]> {
    const results: ScanSQLInjectionResult[] = [];

    try {
      this.logger.log(`Starting SQL injection scan for: ${url}`);

      // 1. Analyze page to get actual parameters
      const pageInfo = await this.analyzePage(url, authConfig);
      this.logger.log(
        `Found URL params: ${JSON.stringify(pageInfo.urlParams)}`,
      );

      // 2. Time-based blind injection detection with baseline
      const timeBasedResults = await this.timeBasedSQLiCheck(
        url,
        pageInfo,
        authConfig,
      );
      results.push(...timeBasedResults);
      this.logger.log(
        `Time-based scan completed: ${timeBasedResults.length} results`,
      );

      // 3. Error-based detection with improved patterns
      const errorBasedResults = await this.errorBasedSQLiCheck(
        url,
        pageInfo,
        authConfig,
      );
      results.push(...errorBasedResults);
      this.logger.log(
        `Error-based scan completed: ${errorBasedResults.length} results`,
      );

      // 4. Python sqlmap script
      const pythonResults = await this.runPythonSQLScanner(
        url,
        pageInfo,
        authConfig,
      );
      results.push(...pythonResults);
      this.logger.log(`Python scan completed: ${pythonResults.length} results`);

      // 5. Deduplicate results if enabled
      if (ScannerConfig.validation.deduplicateResults) {
        const deduplicatedResults = this.deduplicateSQLResults(results);
        this.logger.log(`Total unique results: ${deduplicatedResults.length}`);
        return deduplicatedResults;
      }
    } catch (error) {
      this.logger.error('SQLi scan failed:', error);
    }

    return results;
  }

  private async analyzePage(
    url: string,
    authConfig?: AuthConfig,
  ): Promise<{
    urlParams: string[];
    forms: PageForm[];
  }> {
    // Similar implementation to XSS service
    const urlParams: string[] = [];
    const forms: PageForm[] = [];

    try {
      const urlObj = new URL(url);
      urlObj.searchParams.forEach((value, key) => {
        urlParams.push(key);
        this.logger.debug(`Found URL param: ${key}=${value}`);
      });

      const requestOptions: AxiosRequestConfig = {
        timeout: ScannerConfig.network.timeout,
        headers: {
          'User-Agent': 'SecurityScanner/1.0',
        },
        validateStatus: () => true,
      };

      if (authConfig && requestOptions.headers) {
        if (authConfig.type === 'cookie' && authConfig.cookies) {
          requestOptions.headers['Cookie'] = Object.entries(authConfig.cookies)
            .map(([key, value]) => `${key}=${value}`)
            .join('; ');
        } else if (authConfig.type === 'header' && authConfig.headers) {
          Object.assign(requestOptions.headers, authConfig.headers);
        }
      }

      const response = await axios.get(url, requestOptions);

      const $ = cheerio.load(response.data as string);

      $('form').each((_, form) => {
        const $form = $(form);
        const formInfo: PageForm = {
          action: $form.attr('action') || '',
          method: ($form.attr('method') || 'GET').toUpperCase(),
          inputs: [],
        };

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

    if (urlParams.length === 0 && forms.length === 0) {
      this.logger.warn(
        'No parameters or forms found for SQL injection testing',
      );
    }

    return { urlParams, forms };
  }

  private async timeBasedSQLiCheck(
    url: string,
    pageInfo: { urlParams: string[]; forms: PageForm[] },
    authConfig?: AuthConfig,
  ): Promise<ScanSQLInjectionResult[]> {
    const results: ScanSQLInjectionResult[] = [];

    if (pageInfo.urlParams.length === 0) {
      this.logger.warn('No parameters to test for time-based SQL injection');
      return results;
    }

    const baselineRequestOptions: AxiosRequestConfig = {
      timeout: ScannerConfig.network.timeout,
      validateStatus: () => true,
      headers: {
        'User-Agent': 'SecurityScanner/1.0',
      },
    };

    if (authConfig && baselineRequestOptions.headers) {
      if (authConfig.type === 'cookie' && authConfig.cookies) {
        baselineRequestOptions.headers['Cookie'] = Object.entries(
          authConfig.cookies,
        )
          .map(([key, value]) => `${key}=${value}`)
          .join('; ');
      } else if (authConfig.type === 'header' && authConfig.headers) {
        Object.assign(baselineRequestOptions.headers, authConfig.headers);
      }
    }

    // Get baseline response times
    const baselineTimes: number[] = [];
    for (let i = 0; i < ScannerConfig.sql.baselineAttempts; i++) {
      try {
        const startTime = Date.now();
        await axios.get(url, baselineRequestOptions);
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
    this.logger.debug(
      `Baseline response time: avg=${avgBaseline}ms, max=${maxBaseline}ms`,
    );

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
            await axios.get(testUrl, baselineRequestOptions);
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

        // Add delay between tests
        await new Promise((resolve) => setTimeout(resolve, 500));
      }
    }

    return results;
  }

  private async errorBasedSQLiCheck(
    url: string,
    pageInfo: { urlParams: string[]; forms: PageForm[] },
    authConfig?: AuthConfig,
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

    if (pageInfo.urlParams.length === 0) {
      this.logger.warn('No parameters to test for error-based SQL injection');
      return results;
    }

    const requestOptions: AxiosRequestConfig = {
      timeout: ScannerConfig.network.timeout,
      validateStatus: () => true,
      headers: {
        'User-Agent': 'SecurityScanner/1.0',
      },
    };

    if (authConfig && requestOptions.headers) {
      if (authConfig.type === 'cookie' && authConfig.cookies) {
        requestOptions.headers['Cookie'] = Object.entries(authConfig.cookies)
          .map(([key, value]) => `${key}=${value}`)
          .join('; ');
      } else if (authConfig.type === 'header' && authConfig.headers) {
        Object.assign(requestOptions.headers, authConfig.headers);
      }
    }

    // Test each parameter
    for (const param of pageInfo.urlParams) {
      for (const payload of errorPayloads) {
        const testUrl = this.buildTestUrlWithParam(url, param, payload);

        try {
          const response = await axios.get(testUrl, requestOptions);
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

          // Add delay between tests
          await new Promise((resolve) => setTimeout(resolve, 100));
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
    // Check for 404/500 errors first
    if (
      responseData.includes('404 Not Found') ||
      responseData.includes('500 Internal Server Error')
    ) {
      return { isError: false };
    }

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
      const key = `${result.parameter || 'unknown'}_${result.vulnerable}_${result.method}_${result.databaseType || 'unknown'}_${result.payload}`;

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
    try {
      const url = new URL(baseUrl);
      url.searchParams.set(param, payload);
      return url.toString();
    } catch {
      // Fallback for invalid URLs
      const separator = baseUrl.includes('?') ? '&' : '?';
      return `${baseUrl}${separator}${param}=${encodeURIComponent(payload)}`;
    }
  }

  private async runPythonSQLScanner(
    url: string,
    pageInfo: { urlParams: string[]; forms: PageForm[] },
    authConfig?: AuthConfig,
  ): Promise<ScanSQLInjectionResult[]> {
    return new Promise<ScanSQLInjectionResult[]>((resolve) => {
      const pythonScriptPath = path.join(
        __dirname,
        '..',
        'scripts',
        'sql_scanner.py',
      );

      // Check if script exists
      if (!fs.existsSync(pythonScriptPath)) {
        this.logger.error(`Python script not found: ${pythonScriptPath}`);
        resolve([]);
        return;
      }

      // Pass parameter information to Python script
      const args = [pythonScriptPath, url];
      if (pageInfo.urlParams.length > 0) {
        args.push('--params', pageInfo.urlParams.join(','));
      }

      if (authConfig) {
        if (authConfig.type === 'cookie' && authConfig.cookies) {
          const cookieString = Object.entries(authConfig.cookies)
            .map(([key, value]) => `${key}=${value}`)
            .join('; ');
          args.push('--cookies', cookieString);
        } else if (authConfig.type === 'header' && authConfig.headers) {
          args.push('--headers', JSON.stringify(authConfig.headers));
        }
      }

      this.logger.debug(
        `Running Python SQL scanner with args: ${args.join(' ')}`,
      );

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
          this.logger.debug(`Python stderr: ${data.toString()}`);
        });
      }

      pythonProcess.on('close', (code: number | null) => {
        this.logger.debug(`Python process exited with code ${code}`);

        if (code === 0 && processData.output) {
          try {
            const parsedResults = this.parseJsonSafely(processData.output);
            if (parsedResults) {
              const mappedResults = this.mapPythonSQLResults(parsedResults);
              this.logger.debug(
                `Python scan returned ${mappedResults.length} results`,
              );
              resolve(mappedResults);
              return;
            }
          } catch (error) {
            this.logger.error('Failed to parse Python output:', error);
            this.logger.debug('Python output was:', processData.output);
          }
        }

        resolve([]);
      });

      pythonProcess.on('error', (error) => {
        this.logger.error('Failed to run Python scanner:', error);
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
    } catch (error) {
      this.logger.error('JSON parse error:', error);
      return null;
    }
    return null;
  }

  private mapPythonSQLResults(
    parsedResults: ParsedResult[],
  ): ScanSQLInjectionResult[] {
    return parsedResults.map((result: ParsedResult): ScanSQLInjectionResult => {
      let method:
        | 'time-based'
        | 'error-based'
        | 'boolean-based'
        | 'union-based'
        | 'form_post'
        | 'form_get'
        | 'python-sqlmap' = 'python-sqlmap';

      if (result.method) {
        const validSQLMethods = [
          'time-based',
          'error-based',
          'boolean-based',
          'union-based',
          'form_post',
          'form_get',
          'python-sqlmap',
        ];
        if (validSQLMethods.includes(result.method)) {
          method = result.method as typeof method;
        }
      }

      const mappedResult: ScanSQLInjectionResult = {
        payload: String(result.payload),
        vulnerable: Boolean(result.vulnerable),
        method: method,
      };

      if (result.parameter) mappedResult.parameter = String(result.parameter);
      if (result.url) mappedResult.url = String(result.url);
      if (result.confidence)
        mappedResult.confidence = Number(result.confidence);
      if (result.severity) {
        mappedResult.severity = result.severity as
          | 'low'
          | 'medium'
          | 'high'
          | 'critical';
      }
      if (result.evidence) mappedResult.evidence = String(result.evidence);
      if (result.databaseType) {
        mappedResult.databaseType = result.databaseType as
          | 'mysql'
          | 'postgresql'
          | 'mssql'
          | 'oracle'
          | 'sqlite'
          | 'unknown';
      }
      if (result.injectionType) {
        mappedResult.injectionType = result.injectionType as
          | 'numeric'
          | 'string'
          | 'blind'
          | 'time-blind'
          | 'union';
      }
      if (result.responseTime)
        mappedResult.responseTime = Number(result.responseTime);
      if (result.error) mappedResult.error = String(result.error);

      return mappedResult;
    });
  }
}
