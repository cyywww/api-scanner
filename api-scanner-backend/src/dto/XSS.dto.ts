export interface ScanXSSResult {
  payload: string;
  vulnerable: boolean;
  method:
    | 'static'
    | 'dynamic'
    | 'python'
    | 'form_post'
    | 'form_get'
    | 'url_parameter'
    | 'selenium_dynamic'
    | 'stored';
  severity?: 'low' | 'medium' | 'high' | 'critical';
  confidence?: number; // Confidence score (0-100)
  context?: string; // Vulnerability context
  evidence?: string; // Evidence
  field?: string; // Form field
  parameter?: string; // URL parameter
  url?: string; // Full URL tested
  responseTime?: number; // Response time
  error?: string; // Error message
  recommendation?: string; // Remediation recommendation
}

export interface XSSScanSummary {
  totalTests: number;
  vulnerableTests: number;
  riskLevel: 'safe' | 'low' | 'medium' | 'high' | 'critical';
  scanDuration: number; // Scan duration (in milliseconds)
  targetUrl: string;
  timestamp: Date;
  methods: string[]; // Scanning methods used
}
