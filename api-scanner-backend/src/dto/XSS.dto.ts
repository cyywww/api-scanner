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
    | 'selenium_dynamic';
  severity?: 'low' | 'medium' | 'high' | 'critical';
  confidence?: number; // 0-100 置信度
  context?: string; // 漏洞出现的上下文
  evidence?: string; // 证据
  field?: string; // 如果是表单字段
  parameter?: string; // 如果是URL参数
  url?: string; // 测试的完整URL
  responseTime?: number; // 响应时间
  error?: string; // 错误信息
  recommendation?: string; // 修复建议
}

export interface XSSScanSummary {
  totalTests: number;
  vulnerableTests: number;
  riskLevel: 'safe' | 'low' | 'medium' | 'high' | 'critical';
  scanDuration: number; // 扫描耗时（毫秒）
  targetUrl: string;
  timestamp: Date;
  methods: string[]; // 使用的扫描方法
}
