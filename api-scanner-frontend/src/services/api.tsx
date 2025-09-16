import axios from "axios";
import type { ScanResult, ScanType } from "../types/scan.types";

const BASE_URL = "http://localhost:3000"; // Address of the backend server

// Scan XSS Vulnerabilities
export const scanXSS = async (url: string): Promise<ScanResult[]> => {
  const res = await axios.post<ScanResult[]>(`${BASE_URL}/scan/xss`, { url });
  return res.data;
};

// Scan SQL Injection Vulnerabilities
export const scanSQLInjection = async (url: string): Promise<ScanResult[]> => {
  const res = await axios.post<ScanResult[]>(`${BASE_URL}/scan/sql`, { url });
  return res.data;
};

// Scan All Vulnerabilities at once
export const scanAll = async (
  url: string
): Promise<{
  xss: ScanResult[];
  sql: ScanResult[];
}> => {
  const [xssResult, sqlResult] = await Promise.all([
    scanXSS(url),
    scanSQLInjection(url),
  ]);

  return {
    xss: xssResult,
    sql: sqlResult,
  };
};

// Generic Scanning Function (Extensible to Other Scan Types)
export const scanVulnerability = async (
  url: string,
  scanType: Exclude<ScanType, "all">
): Promise<ScanResult[]> => {
  switch (scanType) {
    case "xss":
      return await scanXSS(url);
    case "sql":
      return await scanSQLInjection(url);
    default:
      throw new Error(`Unsupported scan type: ${scanType}`);
  }
};
