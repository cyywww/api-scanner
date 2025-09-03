import axios from 'axios'

const BASE_URL = 'http://localhost:3000'; // Address of the backend server

// Scan XSS Vulnerabilities
export const scanXSS = async (url: string) => {
  const res = await axios.post(`${BASE_URL}/scan/xss`, { url });
  return res.data;
};

// Scan SQL Injection Vulnerabilities
export const scanSQLInjection = async (url: string) => {
  const res = await axios.post(`${BASE_URL}/scan/sql`, { url });
  return res.data;
};

// Scan All Vulnerabilities at once
export const scanAll = async (url: string) => {
  const [xssResult, sqlResult] = await Promise.all([
    scanXSS(url),
    scanSQLInjection(url)
  ]);
  
  return {
    xss: xssResult,
    sql: sqlResult
  };
};

// Generic Scanning Function (Extensible to Other Scan Types)
export const scanVulnerability = async (url: string, scanType: 'xss' | 'sql' | 'all') => {
  switch (scanType) {
    case 'xss':
      return await scanXSS(url);
    case 'sql':
      return await scanSQLInjection(url);
    case 'all':
      return await scanAll(url);
    default:
      throw new Error(`Unsupported scan type: ${scanType}`);
  }
};