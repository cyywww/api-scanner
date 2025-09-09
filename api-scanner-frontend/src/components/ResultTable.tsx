import React from 'react';

type Result = {
  payload: string;
  vulnerable: boolean;
  method?: string;
  parameter?: string;
  field?: string;
  url?: string;
  confidence?: number;
  severity?: string;
  evidence?: string;
  error?: string;
  responseTime?: number;
  context?: string;
  databaseType?: string;
  injectionType?: string;
};

interface ResultTableProps {
  results: Result[];
  title?: string;
}

export const ResultTable: React.FC<ResultTableProps> = ({ results, title }) => {
  // 对结果进行分组和排序
  const sortedResults = [...results].sort((a, b) => {
    // 先按漏洞状态排序（有漏洞的排前面）
    if (a.vulnerable !== b.vulnerable) {
      return b.vulnerable ? 1 : -1;
    }
    // 再按严重程度排序
    const severityOrder: { [key: string]: number } = { 
      critical: 4, 
      high: 3, 
      medium: 2, 
      low: 1 
    };
    const aSeverity = severityOrder[a.severity || ''] || 0;
    const bSeverity = severityOrder[b.severity || ''] || 0;
    if (aSeverity !== bSeverity) {
      return bSeverity - aSeverity;
    }
    // 最后按置信度排序
    const aConfidence = a.confidence || 0;
    const bConfidence = b.confidence || 0;
    return bConfidence - aConfidence;
  });

  // 统计信息
  const stats = {
    total: results.length,
    vulnerable: results.filter(r => r.vulnerable).length,
    errors: results.filter(r => r.error).length,
    success: results.filter(r => !r.error).length,
    critical: results.filter(r => r.vulnerable && r.severity === 'critical').length,
    high: results.filter(r => r.vulnerable && r.severity === 'high').length,
    medium: results.filter(r => r.vulnerable && r.severity === 'medium').length,
    low: results.filter(r => r.vulnerable && r.severity === 'low').length,
  };

  // 获取方法的显示颜色
  const getMethodColor = (method?: string) => {
    const colors: { [key: string]: string } = {
      'static': 'bg-blue-100 text-blue-800',
      'dynamic': 'bg-purple-100 text-purple-800',
      'python': 'bg-green-100 text-green-800',
      'form_post': 'bg-yellow-100 text-yellow-800',
      'form_get': 'bg-orange-100 text-orange-800',
      'url_parameter': 'bg-indigo-100 text-indigo-800',
      'time-based': 'bg-pink-100 text-pink-800',
      'error-based': 'bg-red-100 text-red-800',
      'boolean-based': 'bg-teal-100 text-teal-800',
      'union-based': 'bg-cyan-100 text-cyan-800',
      'python-sqlmap': 'bg-lime-100 text-lime-800',
    };
    return colors[method || ''] || 'bg-gray-100 text-gray-800';
  };

  // 获取严重程度的显示样式
  const getSeverityStyle = (severity?: string) => {
    const styles: { [key: string]: string } = {
      'critical': 'bg-red-600 text-white',
      'high': 'bg-red-500 text-white',
      'medium': 'bg-yellow-500 text-white',
      'low': 'bg-yellow-300 text-gray-800',
    };
    return styles[severity || ''] || 'bg-gray-200 text-gray-600';
  };

  // 格式化响应时间
  const formatResponseTime = (time?: number) => {
    if (!time) return '-';
    if (time >= 1000) {
      return `${(time / 1000).toFixed(1)}s`;
    }
    return `${time}ms`;
  };

  // 截断长文本
  const truncateText = (text: string, maxLength: number = 50) => {
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength) + '...';
  };

  if (results.length === 0) {
    return (
      <div className="text-center py-8 text-gray-500">
        No scan results yet. Enter a URL and start scanning.
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {title && (
        <h3 className="text-lg font-medium text-gray-700">{title}</h3>
      )}

      {/* 统计摘要 */}
      {stats.vulnerable > 0 && (
        <div className="p-4 bg-red-50 border border-red-200 rounded-lg">
          <div className="flex items-center mb-2">
            <svg className="w-5 h-5 text-red-600 mr-2" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
            </svg>
            <span className="text-red-800 font-semibold">
              {stats.vulnerable} Security {stats.vulnerable === 1 ? 'Vulnerability' : 'Vulnerabilities'} Detected!
            </span>
          </div>
          <div className="text-sm text-red-700 ml-7">
            {stats.critical > 0 && <span className="mr-3">Critical: {stats.critical}</span>}
            {stats.high > 0 && <span className="mr-3">High: {stats.high}</span>}
            {stats.medium > 0 && <span className="mr-3">Medium: {stats.medium}</span>}
            {stats.low > 0 && <span>Low: {stats.low}</span>}
          </div>
        </div>
      )}

      {/* 结果表格 */}
      <div className="overflow-x-auto shadow-sm border border-gray-200 rounded-lg">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-gray-50 border-b border-gray-200">
              <th className="px-3 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Payload
              </th>
              <th className="px-3 py-3 text-center text-xs font-medium text-gray-500 uppercase tracking-wider">
                Status
              </th>
              <th className="px-3 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Method
              </th>
              <th className="px-3 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Target
              </th>
              <th className="px-3 py-3 text-center text-xs font-medium text-gray-500 uppercase tracking-wider">
                Risk
              </th>
              <th className="px-3 py-3 text-center text-xs font-medium text-gray-500 uppercase tracking-wider">
                Confidence
              </th>
              <th className="px-3 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Details
              </th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {sortedResults.map((r, i) => (
              <tr 
                key={i} 
                className={`
                  ${r.vulnerable ? 'bg-red-50 hover:bg-red-100' : 'hover:bg-gray-50'}
                  transition-colors duration-150
                `}
              >
                {/* Payload */}
                <td className="px-3 py-2">
                  <div className="font-mono text-xs break-all max-w-xs" title={r.payload}>
                    {truncateText(r.payload, 40)}
                  </div>
                </td>

                {/* Status */}
                <td className="px-3 py-2 text-center">
                  {r.vulnerable ? (
                    <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-red-100 text-red-800">
                      <svg className="w-3 h-3 mr-1" fill="currentColor" viewBox="0 0 20 20">
                        <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                      </svg>
                      Vulnerable
                    </span>
                  ) : (
                    <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800">
                      <svg className="w-3 h-3 mr-1" fill="currentColor" viewBox="0 0 20 20">
                        <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                      </svg>
                      Safe
                    </span>
                  )}
                </td>

                {/* Method */}
                <td className="px-3 py-2">
                  {r.method && (
                    <span className={`inline-block px-2 py-1 rounded text-xs ${getMethodColor(r.method)}`}>
                      {r.method}
                    </span>
                  )}
                </td>

                {/* Target */}
                <td className="px-3 py-2">
                  <div className="text-xs space-y-1">
                    {r.parameter && (
                      <div>
                        <span className="font-semibold text-gray-600">Param:</span>{' '}
                        <span className="text-gray-900">{r.parameter}</span>
                      </div>
                    )}
                    {r.field && (
                      <div>
                        <span className="font-semibold text-gray-600">Field:</span>{' '}
                        <span className="text-gray-900">{r.field}</span>
                      </div>
                    )}
                    {r.url && (
                      <div className="truncate max-w-xs" title={r.url}>
                        <span className="font-semibold text-gray-600">URL:</span>{' '}
                        <span className="text-gray-900">{truncateText(r.url, 30)}</span>
                      </div>
                    )}
                    {!r.parameter && !r.field && !r.url && (
                      <span className="text-gray-400">-</span>
                    )}
                  </div>
                </td>

                {/* Risk Level */}
                <td className="px-3 py-2 text-center">
                  {r.severity ? (
                    <span 
                      className={`inline-block px-2 py-1 rounded text-xs font-semibold ${getSeverityStyle(r.severity)}`}
                    >
                      {r.severity.toUpperCase()}
                    </span>
                  ) : (
                    <span className="text-gray-400">-</span>
                  )}
                </td>

                {/* Confidence */}
                <td className="px-3 py-2 text-center">
                  {r.confidence ? (
                    <div className="flex items-center justify-center">
                      <div className="w-16 bg-gray-200 rounded-full h-2">
                        <div 
                          className={`h-2 rounded-full ${
                            r.confidence >= 80 ? 'bg-green-500' : 
                            r.confidence >= 60 ? 'bg-yellow-500' : 
                            'bg-red-500'
                          }`}
                          style={{ width: `${r.confidence}%` }}
                        />
                      </div>
                      <span className="ml-2 text-xs font-medium">{r.confidence}%</span>
                    </div>
                  ) : (
                    <span className="text-gray-400">-</span>
                  )}
                </td>

                {/* Details */}
                <td className="px-3 py-2">
                  <div className="text-xs space-y-1">
                    {r.evidence && (
                      <div className="text-green-700">
                        <span className="font-semibold">Evidence:</span>{' '}
                        <span className="break-all">{truncateText(r.evidence, 50)}</span>
                      </div>
                    )}
                    {r.context && (
                      <div className="text-blue-700">
                        <span className="font-semibold">Context:</span>{' '}
                        <span className="break-all">{truncateText(r.context, 50)}</span>
                      </div>
                    )}
                    {r.responseTime && (
                      <div className="text-purple-700">
                        <span className="font-semibold">Response:</span>{' '}
                        {formatResponseTime(r.responseTime)}
                      </div>
                    )}
                    {r.databaseType && (
                      <div className="text-indigo-700">
                        <span className="font-semibold">DB Type:</span>{' '}
                        {r.databaseType}
                      </div>
                    )}
                    {r.injectionType && (
                      <div className="text-teal-700">
                        <span className="font-semibold">Injection:</span>{' '}
                        {r.injectionType}
                      </div>
                    )}
                    {r.error && (
                      <div className="text-red-600">
                        <span className="font-semibold">Error:</span>{' '}
                        <span className="break-all">{truncateText(r.error, 50)}</span>
                      </div>
                    )}
                    {!r.evidence && !r.context && !r.error && !r.responseTime && (
                      <span className="text-gray-400">No details</span>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* 汇总统计 */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 p-4 bg-gray-50 rounded-lg">
        <div className="text-center">
          <div className="text-2xl font-bold text-gray-900">{stats.total}</div>
          <div className="text-xs text-gray-600">Total Tests</div>
        </div>
        <div className="text-center">
          <div className="text-2xl font-bold text-red-600">{stats.vulnerable}</div>
          <div className="text-xs text-gray-600">Vulnerabilities</div>
        </div>
        <div className="text-center">
          <div className="text-2xl font-bold text-green-600">{stats.success}</div>
          <div className="text-xs text-gray-600">Successful Tests</div>
        </div>
        <div className="text-center">
          <div className="text-2xl font-bold text-blue-600">
            {stats.total > 0 
              ? `${Math.round((stats.vulnerable / stats.total) * 100)}%`
              : '0%'}
          </div>
          <div className="text-xs text-gray-600">Detection Rate</div>
        </div>
      </div>

      {/* 建议 */}
      {stats.vulnerable > 0 && (
        <div className="p-4 bg-yellow-50 border border-yellow-200 rounded-lg">
          <h4 className="font-semibold text-yellow-800 mb-2">Security Recommendations:</h4>
          <ul className="text-sm text-yellow-700 space-y-1 list-disc list-inside">
            {results.some(r => r.vulnerable && r.method?.includes('xss')) && (
              <li>Implement proper input validation and output encoding for XSS prevention</li>
            )}
            {results.some(r => r.vulnerable && r.method?.includes('sql')) && (
              <li>Use parameterized queries or prepared statements to prevent SQL injection</li>
            )}
            {results.some(r => r.vulnerable && r.method?.includes('time-based')) && (
              <li>Review database query optimization to prevent time-based attacks</li>
            )}
            <li>Consider implementing a Web Application Firewall (WAF)</li>
            <li>Regularly update and patch your application dependencies</li>
            <li>Conduct regular security audits and penetration testing</li>
          </ul>
        </div>
      )}
    </div>
  );
};