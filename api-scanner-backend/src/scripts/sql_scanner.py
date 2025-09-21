import sys
import json
import requests
import time
import re
import argparse
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup

class AdvancedSQLiScanner:
    def __init__(self, target_url, custom_params=None, cookies=None, headers=None):
        self.target_url = target_url
        self.custom_params = custom_params or []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.results = []
        
        # Handle cookies for authentication
        if cookies:
            for cookie in cookies.split(';'):
                if '=' in cookie:
                    name, value = cookie.strip().split('=', 1)
                    self.session.cookies.set(name, value)
        
        # Handle headers for authentication
        if headers:
            try:
                header_dict = json.loads(headers) if isinstance(headers, str) else headers
                self.session.headers.update(header_dict)
            except:
                pass
        
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
        """Build test URL with payload - only for actual parameters"""
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)
        
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
            return None

    def time_based_sqli_scan(self):
        """Time-based blind SQL injection scan"""
        time_payloads = {
            'mysql': [
                "1' AND SLEEP(5)-- ",
                "1 AND SLEEP(5)-- ",
            ],
            'postgresql': [
                "1' AND pg_sleep(5)-- ",
            ],
            'mssql': [
                "1'; WAITFOR DELAY '00:00:05'-- ",
            ]
        }
        
        # Determine which parameters to test
        params_to_test = []
        parsed = urlparse(self.target_url)
        url_params = parse_qs(parsed.query)
        
        if self.custom_params:
            params_to_test = self.custom_params
            print(f"[INFO] Testing time-based SQL injection on custom params: {params_to_test}", file=sys.stderr)
        elif url_params:
            params_to_test = list(url_params.keys())
            print(f"[INFO] Testing time-based SQL injection on URL params: {params_to_test}", file=sys.stderr)
        else:
            print(f"[INFO] No parameters found for time-based SQL injection testing", file=sys.stderr)
            return
        
        for param in params_to_test:
            for db_type, payloads in time_payloads.items():
                for payload in payloads:
                    try:
                        test_url = self.build_test_url(payload, param)
                        if not test_url:
                            continue
                        
                        start_time = time.time()
                        response = self.session.get(test_url, timeout=10, allow_redirects=False)
                        response_time = time.time() - start_time
                        
                        # Check for login redirect
                        if response.status_code == 302 and 'login' in response.headers.get('Location', '').lower():
                            print(f"[WARNING] Redirected to login page", file=sys.stderr)
                            continue
                        
                        vulnerable = response_time > 4.5
                        
                        self.results.append({
                            'payload': payload,
                            'vulnerable': vulnerable,
                            'method': 'time-based',
                            'parameter': param,
                            'url': test_url,
                            'responseTime': int(response_time * 1000),
                            'databaseType': db_type if vulnerable else None,
                            'injectionType': 'time-blind',
                            'severity': 'high' if vulnerable else None,
                            'confidence': min(95, int((response_time / 5.0) * 100)) if vulnerable else 0,
                            'evidence': f"Response time: {response_time:.2f}s" if vulnerable else None
                        })
                        
                        time.sleep(0.5)
                        
                    except Exception as e:
                        self.results.append({
                            'payload': payload,
                            'vulnerable': False,
                            'method': 'time-based',
                            'parameter': param,
                            'error': str(e)
                        })

    def error_based_sqli_scan(self):
        """Error-based SQL injection scan"""
        error_payloads = [
            "'",
            "' OR '1'='1",
            "1' AND '1'='2",
            "' UNION SELECT NULL-- "
        ]
        
        params_to_test = []
        parsed = urlparse(self.target_url)
        url_params = parse_qs(parsed.query)
        
        if self.custom_params:
            params_to_test = self.custom_params
        elif url_params:
            params_to_test = list(url_params.keys())
        else:
            print(f"[INFO] No parameters found for error-based SQL injection testing", file=sys.stderr)
            return
        
        for param in params_to_test:
            for payload in error_payloads:
                try:
                    test_url = self.build_test_url(payload, param)
                    if not test_url:
                        continue
                        
                    response = self.session.get(test_url, timeout=8, allow_redirects=False)
                    
                    if response.status_code == 302 and 'login' in response.headers.get('Location', '').lower():
                        continue
                    
                    db_type = self.detect_database_type(response.text)
                    vulnerable = db_type != 'unknown'
                    
                    self.results.append({
                        'payload': payload,
                        'vulnerable': vulnerable,
                        'method': 'error-based',
                        'parameter': param,
                        'url': test_url,
                        'databaseType': db_type if vulnerable else None,
                        'injectionType': 'string' if "'" in payload else 'numeric',
                        'severity': 'high' if vulnerable else None,
                        'confidence': 90 if vulnerable else 0,
                        'evidence': self.extract_sql_error(response.text) if vulnerable else None
                    })
                    
                except Exception as e:
                    self.results.append({
                        'payload': payload,
                        'vulnerable': False,
                        'method': 'error-based',
                        'parameter': param,
                        'error': str(e)
                    })

    def union_based_sqli_scan(self):
        """UNION-based SQL injection scan"""
        params_to_test = []
        parsed = urlparse(self.target_url)
        url_params = parse_qs(parsed.query)
        
        if self.custom_params:
            params_to_test = self.custom_params
        elif url_params:
            params_to_test = list(url_params.keys())
        else:
            print(f"[INFO] No parameters found for UNION-based SQL injection testing", file=sys.stderr)
            return
        
        for param in params_to_test:
            # Test for number of columns
            for i in range(1, 8):
                null_string = ','.join(['NULL'] * i)
                payload = f"1' UNION SELECT {null_string}-- "
                
                try:
                    test_url = self.build_test_url(payload, param)
                    if not test_url:
                        continue
                    
                    response = self.session.get(test_url, timeout=5, allow_redirects=False)
                    
                    if response.status_code == 302:
                        continue
                    
                    # Check if UNION was successful (no SQL error)
                    if not self.has_sql_error(response.text):
                        self.results.append({
                            'payload': payload,
                            'vulnerable': True,
                            'method': 'union-based',
                            'parameter': param,
                            'url': test_url,
                            'injectionType': 'union',
                            'severity': 'high',
                            'confidence': 85
                        })
                        break  # Found the right number of columns
                        
                except Exception as e:
                    pass

    def scan_forms(self):
        """Scan forms for SQL injection"""
        try:
            response = self.session.get(self.target_url, timeout=10, allow_redirects=True)
            
            if 'login' in response.url.lower() and 'login' not in self.target_url.lower():
                print(f"[ERROR] Redirected to login page", file=sys.stderr)
                return
            
            soup = BeautifulSoup(response.content, 'html.parser')
            forms = soup.find_all('form')
            
            if len(forms) == 0:
                return
            
            sql_payloads = ["'", "' OR '1'='1"]
            
            for idx, form in enumerate(forms):
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                
                if not action or action == '#':
                    form_url = self.target_url.split('?')[0]
                else:
                    form_url = urljoin(self.target_url, action)
                
                inputs = form.find_all(['input', 'textarea', 'select'])
                form_data = {}
                testable_fields = []
                
                for input_field in inputs:
                    name = input_field.get('name')
                    if name:
                        input_type = input_field.get('type', 'text')
                        if input_type == 'submit':
                            form_data[name] = input_field.get('value', 'Submit')
                        elif input_type not in ['button', 'reset']:
                            form_data[name] = 'test'
                            testable_fields.append(name)
                
                for field_name in testable_fields:
                    for payload in sql_payloads:
                        test_data = form_data.copy()
                        test_data[field_name] = payload
                        
                        try:
                            if method == 'post':
                                resp = self.session.post(form_url, data=test_data, timeout=10)
                            else:
                                resp = self.session.get(form_url, params=test_data, timeout=10)
                            
                            db_type = self.detect_database_type(resp.text)
                            vulnerable = db_type != 'unknown'
                            
                            self.results.append({
                                'payload': payload,
                                'vulnerable': vulnerable,
                                'method': f'form_{method}',
                                'field': field_name,
                                'url': form_url,
                                'databaseType': db_type if vulnerable else None,
                                'severity': 'high' if vulnerable else None,
                                'confidence': 85 if vulnerable else 0
                            })
                            
                        except Exception as e:
                            self.results.append({
                                'payload': payload,
                                'vulnerable': False,
                                'method': f'form_{method}',
                                'field': field_name,
                                'error': str(e)
                            })
                            
        except Exception as e:
            print(f"[ERROR] Form scan failed: {str(e)}", file=sys.stderr)

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
                    start = max(0, match.start() - 50)
                    end = min(len(response_text), match.end() + 50)
                    return response_text[start:end].strip()
        return None

    def run_scan(self):
        """Run complete SQL injection scan"""
        try:
            print(f"[INFO] Starting SQL injection scan for: {self.target_url}", file=sys.stderr)
            
            # Check access
            test_response = self.session.get(self.target_url, timeout=10, allow_redirects=True)
            if 'login' in test_response.url.lower() and 'login' not in self.target_url.lower():
                print(f"[ERROR] Target URL redirects to login. Please provide valid session cookies.", file=sys.stderr)
                return []
            
            parsed = urlparse(self.target_url)
            url_params = parse_qs(parsed.query)
            
            # Only run parameter-based tests if we have parameters
            if self.custom_params or url_params:
                self.error_based_sqli_scan()
                self.time_based_sqli_scan()
                self.union_based_sqli_scan()
            else:
                print(f"[INFO] No URL parameters found, checking for forms", file=sys.stderr)
            
            # Always scan forms if they exist
            self.scan_forms()
            
            print(f"[INFO] Scan completed. Total tests: {len(self.results)}", file=sys.stderr)
            
        except Exception as e:
            print(f"[ERROR] Scan failed: {str(e)}", file=sys.stderr)
        
        return self.results

def main():
    parser = argparse.ArgumentParser(description='Advanced SQL Injection Scanner')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('--params', help='Comma-separated list of parameters', default='')
    parser.add_argument('--cookies', help='Cookies for authentication', default='')
    parser.add_argument('--headers', help='Headers for authentication (JSON format)', default='')
    
    args = parser.parse_args()
    
    custom_params = []
    if args.params:
        custom_params = [p.strip() for p in args.params.split(',') if p.strip()]
    
    scanner = AdvancedSQLiScanner(args.url, custom_params, args.cookies, args.headers)
    results = scanner.run_scan()
    
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()