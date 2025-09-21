import axios from "axios";
import type { ScanResult, ScanType } from "../types/scan.types";

const BASE_URL = "http://localhost:3000";

interface AuthConfig {
  type: 'none' | 'cookie' | 'header';
  cookies?: Record<string, string>;
  headers?: Record<string, string>;
}

// Scan XSS Vulnerabilities
export const scanXSS = async (url: string, authConfig?: AuthConfig): Promise<ScanResult[]> => {
  try {
    const res = await axios.post<ScanResult[]>(`${BASE_URL}/scan/xss`, { 
      url,
      authConfig 
    });
    return res.data;
  } catch (error) {
    console.error('XSS scan failed:', error);
    return [];
  }
};

// Scan SQL Injection Vulnerabilities
export const scanSQLInjection = async (url: string, authConfig?: AuthConfig): Promise<ScanResult[]> => {
  try {
    const res = await axios.post<ScanResult[]>(`${BASE_URL}/scan/sql`, { 
      url,
      authConfig 
    });
    return res.data;
  } catch (error) {
    console.error('SQL injection scan failed:', error);
    return [];
  }
};

// Scan All Vulnerabilities at once
export const scanAll = async (
  url: string,
  authConfig?: AuthConfig
): Promise<{
  xss: ScanResult[];
  sql: ScanResult[];
}> => {
  const [xssResult, sqlResult] = await Promise.all([
    scanXSS(url, authConfig),
    scanSQLInjection(url, authConfig),
  ]);

  return {
    xss: xssResult,
    sql: sqlResult,
  };
};

// Generic Scanning Function (Extensible to Other Scan Types)
export const scanVulnerability = async (
  url: string,
  scanType: Exclude<ScanType, "all">,
  authConfig?: AuthConfig
): Promise<ScanResult[]> => {
  switch (scanType) {
    case "xss":
      return await scanXSS(url, authConfig);
    case "sql":
      return await scanSQLInjection(url, authConfig);
    default:
      throw new Error(`Unsupported scan type: ${scanType}`);
  }
};