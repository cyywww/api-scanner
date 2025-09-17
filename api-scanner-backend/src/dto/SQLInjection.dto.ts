export interface ScanSQLInjectionResult {
  payload: string;
  vulnerable: boolean;
  method:
    | 'time-based'
    | 'error-based'
    | 'boolean-based'
    | 'union-based'
    | 'python-sqlmap';
  severity?: 'low' | 'medium' | 'high' | 'critical';
  confidence?: number;
  evidence?: string;
  responseTime?: number;
  parameter?: string;
  url?: string;
  databaseType?:
    | 'mysql'
    | 'postgresql'
    | 'mssql'
    | 'oracle'
    | 'sqlite'
    | 'unknown';
  injectionType?: 'numeric' | 'string' | 'blind' | 'time-blind' | 'union';
  error?: string;
  recommendation?: string;
}

export interface SQLIScanSummary {
  totalTests: number;
  vulnerableTests: number;
  riskLevel: 'safe' | 'low' | 'medium' | 'high' | 'critical';
  scanDuration: number;
  targetUrl: string;
  timestamp: Date;
  detectedDatabases: string[];
  methods: string[];
}
