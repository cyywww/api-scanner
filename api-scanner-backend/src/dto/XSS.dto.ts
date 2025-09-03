export interface ScanXSSResult {
  payload: string;
  vulnerable: boolean;
  error?: string;
}
