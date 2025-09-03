export interface ScanSQLInjectionResult {
  payload: string;
  vulnerable: boolean;
  error?: string;
}
