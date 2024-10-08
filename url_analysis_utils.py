import whois
import dns.resolver
import ssl
import OpenSSL
import socket
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs
from typing import Dict, Optional, List, Union, Any
from requests.exceptions import RequestException
from urllib3.exceptions import HTTPError
import time
import re
import concurrent.futures
import logging
from functools import lru_cache

# 로깅 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@lru_cache(maxsize=100)
def analyze_domain(url: str) -> Dict[str, Optional[str]]:
    parsed = urlparse(url)
    return {
        'domain': parsed.netloc,
        'tld': parsed.netloc.split('.')[-1],
        'subdomain': '.'.join(parsed.netloc.split('.')[:-2]) if len(parsed.netloc.split('.')) > 2 else None
    }

def analyze_url_structure(url: str) -> Dict[str, Union[int, bool]]:
    return {
        'length': len(url),
        'ip_in_url': bool(re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', url)),
        'abnormal_chars': bool(re.search(r'[^a-zA-Z0-9-._~:/?#\[\]@!$&\'()*+,;%=]', url)),
        'num_params': len(parse_qs(urlparse(url).query)),
        'num_subdomains': len(urlparse(url).netloc.split('.')) - 2
    }

@lru_cache(maxsize=100)
def get_whois_info(domain: str) -> Dict[str, Any]:
    try:
        w = whois.whois(domain)
        return {
            "registrar": w.registrar,
            "creation_date": w.creation_date,
            "expiration_date": w.expiration_date,
            "name_servers": w.name_servers,
            "registrant": w.registrant,
            "admin": w.admin,
            "tech": w.tech
        }
    except Exception as e:
        logger.error(f"Error fetching WHOIS info for {domain}: {str(e)}")
        return {"error": str(e)}

def get_dns_records(domain: str) -> Dict[str, List[str]]:
    records = {}
    for record_type in ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records[record_type] = [str(rdata) for rdata in answers]
        except dns.resolver.NoAnswer:
            records[record_type] = []
        except Exception as e:
            logger.error(f"Error fetching {record_type} records for {domain}: {str(e)}")
            records[record_type] = [f"Error: {str(e)}"]
    return records

def get_ssl_info(domain: str) -> Dict[str, Any]:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                cert = secure_sock.getpeercert()
        return {
            "subject": dict(x[0] for x in cert['subject']),
            "issuer": dict(x[0] for x in cert['issuer']),
            "version": cert['version'],
            "serialNumber": cert['serialNumber'],
            "notBefore": cert['notBefore'],
            "notAfter": cert['notAfter'],
            "subjectAltName": cert.get('subjectAltName', [])
        }
    except Exception as e:
        logger.error(f"Error fetching SSL info for {domain}: {str(e)}")
        return {"error": str(e)}

def get_robots_txt(domain: str) -> str:
    try:
        url = f"https://{domain}/robots.txt"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return response.text
        else:
            return f"No robots.txt found (Status code: {response.status_code})"
    except Exception as e:
        logger.error(f"Error fetching robots.txt for {domain}: {str(e)}")
        return f"Error fetching robots.txt: {str(e)}"

def get_http_headers(url: str) -> Dict[str, str]:
    try:
        response = requests.head(url, timeout=10)
        return dict(response.headers)
    except Exception as e:
        logger.error(f"Error fetching HTTP headers for {url}: {str(e)}")
        return {"error": str(e)}

def analyze_content(url: str, content: str) -> Dict[str, Any]:
    soup = BeautifulSoup(content, 'html.parser')
    
    meta_tags = {meta.get('name'): meta.get('content') for meta in soup.find_all('meta') if meta.get('name')}
    headers = {f'h{i}': [header.text for header in soup.find_all(f'h{i}')] for i in range(1, 7)}
    paragraphs = [p.text for p in soup.find_all('p')]
    
    # 추가된 분석 요소들
    links = soup.find_all('a')
    forms = soup.find_all('form')
    inputs = soup.find_all('input')
    scripts = soup.find_all('script')
    
    return {
        'title': soup.title.string if soup.title else None,
        'meta_tags': meta_tags,
        'headers': headers,
        'links': [link.get('href') for link in links],
        'forms': [{'action': form.get('action'), 'method': form.get('method')} for form in forms],
        'external_resources': [src.get('src') for src in soup.find_all(['img', 'script', 'iframe', 'link']) if src.get('src') and src.get('src').startswith('http')],
        'paragraphs': paragraphs[:5],  # 처음 5개 단락만 저장
        'word_count': len(content.split()),
        'has_login_form': bool(soup.find('form', {'action': re.compile(r'login|signin', re.I)})),
        'password_inputs': len([input for input in inputs if input.get('type') == 'password']),
        'hidden_inputs': len([input for input in inputs if input.get('type') == 'hidden']),
        'iframes': len(soup.find_all('iframe')),
        'external_links_ratio': len([link for link in links if link.get('href') and link.get('href').startswith('http')]) / len(links) if links else 0,
        'js_obfuscation': any('eval(' in script.string or 'unescape(' in script.string for script in scripts if script.string),
        'suspicious_keywords': [keyword for keyword in ['login', 'password', 'credit card', 'ssn', 'social security'] if keyword in content.lower()],
        'favicon': soup.find('link', rel='shortcut icon') or soup.find('link', rel='icon'),
        'ssl_seal': bool(soup.find(alt=re.compile(r'ssl|secure|certificate', re.I))),
        'copyright_info': bool(soup.find(string=re.compile(r'©|copyright', re.I))),
        'url_in_page': url.lower() in content.lower(),
        'form_actions': [form.get('action') for form in forms],
        'external_scripts': len([script for script in scripts if script.get('src') and script.get('src').startswith('http')]),
        'data_uri_usage': len(re.findall(r'data:(?:\w+\/\w+);base64,', content)),
        'inline_styles': len(soup.find_all(style=True)),
    }

def analyze_javascript(content: str) -> Dict[str, Any]:
    scripts = re.findall(r'<script\b[^>]*>(.*?)</script>', content, re.DOTALL)
    suspicious_patterns = [
        r'document\.cookie',
        r'window\.location',
        r'eval\(',
        r'fromCharCode',
        r'atob\(',
        r'btoa\(',
        r'unescape\(',
        r'escape\(',
        r'decodeURIComponent\(',
        r'encodeURIComponent\('
    ]
    return {
        'script_count': len(scripts),
        'suspicious_scripts': [script for script in scripts if any(re.search(pattern, script) for pattern in suspicious_patterns)],
        'external_scripts': re.findall(r'<script[^>]+src=["\']([^"\']+)', content)
    }

def get_url_content(url: str, timeout: int = 10, max_retries: int = 3, retry_delay: int = 5) -> Dict[str, Optional[Any]]:
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    
    result = {
        "content": None,
        "whois_info": None,
        "dns_records": None,
        "ssl_info": None,
        "robots_txt": None,
        "http_headers": None,
        "domain_analysis": None,
        "url_structure": None,
        "content_analysis": None,
        "javascript_analysis": None
    }
    
    domain = urlparse(url).netloc
    
    for attempt in range(max_retries):
        try:
            response = requests.get(url, headers=headers, timeout=timeout)
            if response.status_code == 200:
                with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                    future_domain = executor.submit(analyze_domain, url)
                    future_url = executor.submit(analyze_url_structure, url)
                    future_whois = executor.submit(get_whois_info, domain)
                    future_dns = executor.submit(get_dns_records, domain)
                    future_ssl = executor.submit(get_ssl_info, domain)

                result["domain_analysis"] = future_domain.result()
                result["url_structure"] = future_url.result()
                result["whois_info"] = future_whois.result()
                result["dns_records"] = future_dns.result()
                result["ssl_info"] = future_ssl.result()
                result["robots_txt"] = get_robots_txt(domain)
                result["http_headers"] = get_http_headers(url)
                result["content_analysis"] = analyze_content(url, response.text)
                result["javascript_analysis"] = analyze_javascript(response.text)
                
                return result
            else:
                logger.warning(f"Received status code {response.status_code} from {url}")
                result["content"] = f"Unable to fetch content. Status code: {response.status_code}"
                return result
        except (RequestException, HTTPError, socket.error) as e:
            logger.warning(f"Error fetching content from {url} (Attempt {attempt + 1}/{max_retries}): {str(e)}")
            if attempt < max_retries - 1:
                logger.info(f"Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
            else:
                logger.error(f"Unable to fetch content after {max_retries} attempts. Error: {str(e)}")
                result["content"] = f"Unable to fetch content after {max_retries} attempts. Error: {str(e)}"
                return result

def generate_prompt(url: str, url_data: Dict[str, Any]) -> str:
    return f"""Analyze the following URL and its content in detail, then provide a response in this exact format:

Classification: [Benign/Suspicious/Malicious]
Suspicion Level: [A number from 0-100]
URL Analysis:
1. [Key point about the URL structure]
2. [Key point about the domain]
3. [Any additional relevant point about the URL]
Content Analysis:
1. [First key point about the content]
2. [Second key point about the content]
3. [Third key point about the content]
4. [Fourth key point about the content]
5. [Fifth key point about the content]
Overall Assessment:
1. [First key point combining URL and content analysis]
2. [Second key point combining URL and content analysis]
3. [Third key point combining URL and content analysis]

Conclusion:
Safety: [Overall safety assessment]
Key Findings: [Brief summary of main analysis points]
Recommendation: [Advice for users regarding this URL]

URL: {url}

Additional Information:
Domain Analysis: {url_data['domain_analysis']}
URL Structure: {url_data['url_structure']}
WHOIS Info: {url_data['whois_info']}
DNS Records: {url_data['dns_records']}
SSL Info: {url_data['ssl_info']}
Robots.txt: {url_data['robots_txt']}
HTTP Headers: {url_data['http_headers']}
Content Analysis: {url_data['content_analysis']}
JavaScript Analysis: {url_data['javascript_analysis']}

Note: Pay special attention to all provided information, looking for any suspicious elements, inconsistencies, or indicators of malicious intent. If certain information is not available, base your analysis on the available data.

Provide your analysis below:
"""

if __name__ == "__main__":
    url = "https://www.naver.com"  # 테스트할 URL을 여기에 입력하세요
    url_data = get_url_content(url)
    prompt = generate_prompt(url, url_data)
    print(prompt)