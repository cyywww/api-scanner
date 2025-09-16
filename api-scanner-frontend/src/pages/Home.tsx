
import { useState } from 'react';
import { scanXSS, scanSQLInjection } from '../services/api';
import { ResultTable } from '../components/ResultTable';
import type { ScanResult } from '../types/scan.types';

export default function Home() {
  const [url, setUrl] = useState('');
  const [xssResults, setXssResults] = useState<ScanResult[]>([]);
  const [sqlResults, setSqlResults] = useState<ScanResult[]>([]);
  const [xssLoading, setXssLoading] = useState(false);
  const [sqlLoading, setSqlLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('summary');

  const handleXSSScan = async () => {
    setXssLoading(true);
    // Clear all results.
    setXssResults([]);
    setSqlResults([]);
    try {
      const data = await scanXSS(url);
      setXssResults(data);
      setActiveTab('xss');  // Switch to the XSS tab directly.
    } catch (err) {
      console.error(err);
    } finally {
      setXssLoading(false);
    }
  };

  const handleSQLScan = async () => {
    setSqlLoading(true);
    // Clear all results.
    setSqlResults([]);
    setXssResults([]);
    try {
      const data = await scanSQLInjection(url);
      setSqlResults(data);
      setActiveTab('sql');  // Switch to the SQL tab directly.
    } catch (err) {
      console.error(err);
    } finally {
      setSqlLoading(false);
    }
  };

  const handleScanAll = async () => {
    setActiveTab('summary');
    // Set loading state.
    setXssLoading(true);
    setSqlLoading(true);
    // Clear all results.
    setXssResults([]);
    setSqlResults([]);
    
    try {
      // Execute two scans in parallel.
      const [xssData, sqlData] = await Promise.all([
        scanXSS(url),
        scanSQLInjection(url)
      ]);
      
      setXssResults(xssData);
      setSqlResults(sqlData);
    } catch (err) {
      console.error(err);
    } finally {
      setXssLoading(false);
      setSqlLoading(false);
    }
  };

  const xssVulnerabilities = xssResults.filter(r => r.vulnerable).length;
  const sqlVulnerabilities = sqlResults.filter(r => r.vulnerable).length;
  const totalVulnerabilities = xssVulnerabilities + sqlVulnerabilities;
  const hasResults = xssResults.length > 0 || sqlResults.length > 0;

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100">
      <div className="container mx-auto px-4 py-12 max-w-7xl">
        {/* Header */}
        <div className="text-center mb-12">
          <div className="inline-flex items-center justify-center w-20 h-20 bg-gradient-to-br from-blue-500 to-purple-600 rounded-full mb-6">
            <svg className="w-10 h-10 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </div>
          <h1 className="text-5xl font-bold text-gray-900 mb-4">API Scanner</h1>
          <p className="text-gray-600 text-lg max-w-2xl mx-auto">
            Detect XSS and SQL Injection vulnerabilities in your web applications
          </p>
        </div>

        {/* URL Input Card */}
        <div className="bg-white rounded-2xl shadow-xl p-8 mb-8">
          <label className="block text-sm font-medium text-gray-700 mb-3">Target URL</label>
          <div className="relative">
            <input
              type="text"
              placeholder="http://localhost/vulnerabilities/xss_r/?name=test"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="w-full px-6 py-4 pr-12 text-lg border-2 border-gray-200 rounded-xl focus:border-blue-500 focus:ring-4 focus:ring-blue-100 focus:outline-none transition-all"
            />
            <svg className="absolute right-4 top-1/2 -translate-y-1/2 w-6 h-6 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
            </svg>
          </div>
        </div>

        {/* Scan Controls */}
        <div className="bg-white rounded-2xl shadow-xl p-8 mb-8">
          <h2 className="text-xl font-semibold text-gray-800 mb-6">Scan Controls</h2>
          <div className="grid md:grid-cols-3 gap-4">
            <button
              onClick={handleXSSScan}
              disabled={xssLoading || !url.trim()}
              className={`relative overflow-hidden group py-4 px-6 rounded-xl font-semibold text-white transition-all duration-300 ${
                xssLoading || !url.trim()
                  ? 'bg-gray-400 cursor-not-allowed'
                  : 'bg-red-500 hover:bg-red-600 hover:shadow-lg transform hover:-translate-y-1'
              }`}
            >
              {xssLoading ? (
                <span className="flex items-center justify-center">
                  <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Scanning XSS...
                </span>
              ) : (
                <span className="flex items-center justify-center">
                  <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                  </svg>
                  Start XSS Scan
                </span>
              )}
            </button>

            <button
              onClick={handleSQLScan}
              disabled={sqlLoading || !url.trim()}
              className={`relative overflow-hidden group py-4 px-6 rounded-xl font-semibold text-white transition-all duration-300 ${
                sqlLoading || !url.trim()
                  ? 'bg-gray-400 cursor-not-allowed'
                  : 'bg-blue-500 hover:bg-blue-600 hover:shadow-lg transform hover:-translate-y-1'
              }`}
            >
              {sqlLoading ? (
                <span className="flex items-center justify-center">
                  <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Scanning SQL...
                </span>
              ) : (
                <span className="flex items-center justify-center">
                  <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4" />
                  </svg>
                  Start SQL Injection Scan
                </span>
              )}
            </button>

            <button
              onClick={handleScanAll}
              disabled={xssLoading || sqlLoading || !url.trim()}
              className={`relative overflow-hidden group py-4 px-6 rounded-xl font-semibold text-white transition-all duration-300 ${
                xssLoading || sqlLoading || !url.trim()
                  ? 'bg-gray-400 cursor-not-allowed'
                  : 'bg-gradient-to-r from-purple-500 to-indigo-600 hover:from-purple-600 hover:to-indigo-700 hover:shadow-lg transform hover:-translate-y-1'
              }`}
            >
              {xssLoading || sqlLoading ? (
                <span className="flex items-center justify-center">
                  <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Scanning All...
                </span>
              ) : (
                <span className="flex items-center justify-center">
                  <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                  </svg>
                  Run All Security Scans
                </span>
              )}
            </button>
          </div>
        </div>

        {/* Results Section */}
        {hasResults && (
          <div className="bg-white rounded-2xl shadow-xl overflow-hidden">
            {/* Alert Banner */}
            {totalVulnerabilities > 0 && (
              <div className="bg-gradient-to-r from-red-500 to-red-600 p-6 text-white">
                <div className="flex items-center">
                  <svg className="h-8 w-8 mr-3" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                  </svg>
                  <div>
                    <h3 className="text-xl font-bold">
                      {totalVulnerabilities} Security {totalVulnerabilities === 1 ? 'Vulnerability' : 'Vulnerabilities'} Detected
                    </h3>
                    <p className="text-red-100 mt-1">
                      Immediate action required to secure your application
                    </p>
                  </div>
                </div>
              </div>
            )}

            {/* Tabs */}
            <div className="border-b border-gray-200 bg-gray-50">
              <nav className="flex -mb-px px-6">
                <button
                  onClick={() => setActiveTab('summary')}
                  className={`py-4 px-6 text-sm font-medium border-b-2 transition-all ${
                    activeTab === 'summary'
                      ? 'border-blue-500 text-blue-600 bg-white'
                      : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                  }`}
                >
                  <svg className="w-4 h-4 inline mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                  </svg>
                  Summary
                </button>
                <button
                  onClick={() => setActiveTab('xss')}
                  className={`py-4 px-6 text-sm font-medium border-b-2 transition-all ${
                    activeTab === 'xss'
                      ? 'border-red-500 text-red-600 bg-white'
                      : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                  }`}
                >
                  XSS
                  <span className={`ml-2 px-2 py-1 text-xs rounded-full ${
                    xssVulnerabilities > 0 ? 'bg-red-100 text-red-600' : 'bg-gray-100 text-gray-600'
                  }`}>
                    {xssResults.length}
                  </span>
                </button>
                <button
                  onClick={() => setActiveTab('sql')}
                  className={`py-4 px-6 text-sm font-medium border-b-2 transition-all ${
                    activeTab === 'sql'
                      ? 'border-blue-500 text-blue-600 bg-white'
                      : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                  }`}
                >
                  SQL Injection
                  <span className={`ml-2 px-2 py-1 text-xs rounded-full ${
                    sqlVulnerabilities > 0 ? 'bg-red-100 text-red-600' : 'bg-gray-100 text-gray-600'
                  }`}>
                    {sqlResults.length}
                  </span>
                </button>
              </nav>
            </div>

            {/* Tab Content */}
            <div className="p-8">
              {activeTab === 'summary' && (
                <div className="space-y-8">
                  {/* Statistics Grid */}
                  <div className="grid md:grid-cols-4 gap-6">
                    <div className="bg-gradient-to-br from-gray-50 to-gray-100 rounded-xl p-6 text-center">
                      <div className="text-4xl font-bold text-gray-900 mb-2">
                        {xssResults.length + sqlResults.length}
                      </div>
                      <div className="text-sm font-medium text-gray-600">Total Tests</div>
                    </div>
                    <div className="bg-gradient-to-br from-red-50 to-red-100 rounded-xl p-6 text-center">
                      <div className="text-4xl font-bold text-red-600 mb-2">
                        {totalVulnerabilities}
                      </div>
                      <div className="text-sm font-medium text-gray-600">Vulnerabilities</div>
                    </div>
                    <div className="bg-gradient-to-br from-green-50 to-green-100 rounded-xl p-6 text-center">
                      <div className="text-4xl font-bold text-green-600 mb-2">
                        {xssResults.length + sqlResults.length - totalVulnerabilities}
                      </div>
                      <div className="text-sm font-medium text-gray-600">Safe Tests</div>
                    </div>
                    <div className="bg-gradient-to-br from-blue-50 to-blue-100 rounded-xl p-6 text-center">
                      <div className="text-4xl font-bold text-blue-600 mb-2">
                        {xssResults.length + sqlResults.length > 0 
                          ? `${Math.round((totalVulnerabilities / (xssResults.length + sqlResults.length)) * 100)}%`
                          : '0%'}
                      </div>
                      <div className="text-sm font-medium text-gray-600">Risk Score</div>
                    </div>
                  </div>

                  {/* Vulnerability Breakdown */}
                  <div className="grid md:grid-cols-2 gap-6">
                    <div className="bg-gray-50 rounded-xl p-6">
                      <h3 className="font-semibold text-gray-800 mb-4 flex items-center">
                        <svg className="w-5 h-5 mr-2 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                        </svg>
                        XSS Vulnerabilities
                      </h3>
                      <div className="text-3xl font-bold text-red-600 mb-2">{xssVulnerabilities}</div>
                      <div className="text-sm text-gray-600">
                        Found in {xssResults.length} test{xssResults.length !== 1 ? 's' : ''}
                      </div>
                    </div>
                    <div className="bg-gray-50 rounded-xl p-6">
                      <h3 className="font-semibold text-gray-800 mb-4 flex items-center">
                        <svg className="w-5 h-5 mr-2 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4" />
                        </svg>
                        SQL Injection Vulnerabilities
                      </h3>
                      <div className="text-3xl font-bold text-blue-600 mb-2">{sqlVulnerabilities}</div>
                      <div className="text-sm text-gray-600">
                        Found in {sqlResults.length} test{sqlResults.length !== 1 ? 's' : ''}
                      </div>
                    </div>
                  </div>

                  {/* Recommendations */}
                  {totalVulnerabilities > 0 && (
                    <div className="bg-yellow-50 border-l-4 border-yellow-400 rounded-xl p-6">
                      <h4 className="font-semibold text-yellow-800 mb-3 flex items-center">
                        <svg className="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20">
                          <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
                        </svg>
                        Security Recommendations
                      </h4>
                      <ul className="text-sm text-yellow-700 space-y-2">
                        {xssVulnerabilities > 0 && (
                          <li className="flex items-start">
                            <span className="text-yellow-500 mr-2">•</span>
                            Implement proper input validation and output encoding to prevent XSS attacks
                          </li>
                        )}
                        {sqlVulnerabilities > 0 && (
                          <li className="flex items-start">
                            <span className="text-yellow-500 mr-2">•</span>
                            Use parameterized queries or prepared statements for all database operations
                          </li>
                        )}
                        <li className="flex items-start">
                          <span className="text-yellow-500 mr-2">•</span>
                          Deploy a Web Application Firewall (WAF) for additional protection
                        </li>
                        <li className="flex items-start">
                          <span className="text-yellow-500 mr-2">•</span>
                          Conduct regular security audits and penetration testing
                        </li>
                        <li className="flex items-start">
                          <span className="text-yellow-500 mr-2">•</span>
                          Keep all dependencies and frameworks up to date
                        </li>
                      </ul>
                    </div>
                  )}
                </div>
              )}

              {activeTab === 'xss' && (
                <div>
                  <div className="mb-6">
                    <h3 className="text-lg font-semibold text-gray-800 mb-2">XSS Scan Results</h3>
                    <p className="text-sm text-gray-600">
                      Cross-Site Scripting vulnerability test results for {url}
                    </p>
                  </div>
                  <ResultTable results={xssResults} type="xss" />
                </div>
              )}

              {activeTab === 'sql' && (
                <div>
                  <div className="mb-6">
                    <h3 className="text-lg font-semibold text-gray-800 mb-2">SQL Injection Scan Results</h3>
                    <p className="text-sm text-gray-600">
                      SQL Injection vulnerability test results for {url}
                    </p>
                  </div>
                  <ResultTable results={sqlResults} type="sql" />
                </div>
              )}
            </div>
          </div>
        )}

        {/* Empty State */}
        {!hasResults && !xssLoading && !sqlLoading && (
          <div className="bg-white rounded-2xl shadow-xl p-12 text-center">
            <svg className="mx-auto h-24 w-24 text-gray-300 mb-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
            <h3 className="text-xl font-semibold text-gray-900 mb-2">No Scan Results Yet</h3>
            <p className="text-gray-500 mb-6">Enter a URL and run a security scan to detect vulnerabilities</p>
            <div className="flex justify-center space-x-4">
              <div className="flex items-center text-sm text-gray-600">
                <span className="w-8 h-8 bg-red-100 text-red-600 rounded-full flex items-center justify-center font-semibold mr-2">1</span>
                Enter target URL
              </div>
              <div className="flex items-center text-sm text-gray-600">
                <span className="w-8 h-8 bg-blue-100 text-blue-600 rounded-full flex items-center justify-center font-semibold mr-2">2</span>
                Select scan type
              </div>
              <div className="flex items-center text-sm text-gray-600">
                <span className="w-8 h-8 bg-green-100 text-green-600 rounded-full flex items-center justify-center font-semibold mr-2">3</span>
                View results
              </div>
            </div>
          </div>
        )}

        {/* Loading State */}
        {(xssLoading || sqlLoading) && !hasResults && (
          <div className="bg-white rounded-2xl shadow-xl p-12">
            <div className="flex flex-col items-center">
              <div className="relative">
                <div className="w-20 h-20 border-4 border-gray-200 rounded-full"></div>
                <div className="w-20 h-20 border-4 border-blue-500 rounded-full animate-spin absolute top-0 left-0 border-t-transparent"></div>
              </div>
              <h3 className="text-xl font-semibold text-gray-900 mt-6 mb-2">Scanning in Progress</h3>
              <p className="text-gray-500 text-center max-w-md">
                {xssLoading && sqlLoading ? 'Running comprehensive security scans...' :
                 xssLoading ? 'Detecting XSS vulnerabilities...' :
                 'Detecting SQL injection vulnerabilities...'}
              </p>
              <div className="mt-6 space-y-2">
                {xssLoading && (
                  <div className="flex items-center text-sm text-gray-600">
                    <svg className="animate-spin h-4 w-4 mr-2 text-red-500" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    Testing XSS payloads...
                  </div>
                )}
                {sqlLoading && (
                  <div className="flex items-center text-sm text-gray-600">
                    <svg className="animate-spin h-4 w-4 mr-2 text-blue-500" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    Testing SQL injection vectors...
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}