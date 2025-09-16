/*
Common interface for scan results
Used for XSS and SQL injection scan results
 */
export interface ScanResult {
  // Payload for testing
  payload: string;
  // Whether a vulnerability was found
  vulnerable: boolean;
  // Detection method
  method?: string;
  // Tested Parameter name
  parameter?: string;
  // Form field name
  field?: string;
  // Tested Full URL
  url?: string;
  // Confidence (0-100)
  confidence?: number;
  // Severity level
  severity?: 'low' | 'medium' | 'high' | 'critical';
  // Vulnerability evidence
  evidence?: string;
  // Error message
  error?: string;
  // Response time (in milliseconds)
  responseTime?: number;
  // Vulnerability context
  context?: string;
  // Database type (SQL injection only)
  databaseType?: string;
  // Injection type (SQL injection only)
  injectionType?: string;
}

// Scan method type
export type ScanMethod =
  | 'static'
  | 'dynamic'
  | 'python'
  | 'form_post'
  | 'form_get'
  | 'url_parameter'
  | 'selenium_dynamic'
  | 'time-based'
  | 'error-based'
  | 'boolean-based'
  | 'union-based'
  | 'python-sqlmap';

// Scan type
export type ScanType = 'xss' | 'sql' | 'all';

// Scan request interface
export interface ScanRequest {
  url: string;
  params?: string[];
}

// Scan response interface
export interface ScanResponse {
  results: ScanResult[];
  summary?: {
    totalTests: number;
    vulnerableTests: number;
    riskLevel: 'safe' | 'low' | 'medium' | 'high' | 'critical';
    scanDuration: number;
    targetUrl: string;
    timestamp: Date;
  };
}

// Props interface for the ResultTable component
export interface ResultTableProps {
  results: ScanResult[];
  type: 'xss' | 'sql';
}