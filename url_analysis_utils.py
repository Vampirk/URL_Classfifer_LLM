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
from typing import Dict, Any

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

def summarize_url_data(url_data: Dict[str, Any]) -> str:
    summary = []
    
    # Domain and URL Structure
    domain_info = url_data.get('domain_analysis', {})
    url_structure = url_data.get('url_structure', {})
    summary.append(f"Domain: {domain_info.get('domain', 'N/A')}, TLD: {domain_info.get('tld', 'N/A')}")
    summary.append(f"URL Length: {url_structure.get('length', 'N/A')}, Subdomains: {url_structure.get('num_subdomains', 'N/A')}")
    summary.append(f"Abnormal Chars: {url_structure.get('abnormal_chars', 'N/A')}, IP in URL: {url_structure.get('ip_in_url', 'N/A')}")

    # WHOIS Info
    whois_info = url_data.get('whois_info', {})
    summary.append(f"Registrar: {whois_info.get('registrar', 'N/A')}, Creation Date: {whois_info.get('creation_date', 'N/A')}")

    # SSL Info
    ssl_info = url_data.get('ssl_info', {})
    summary.append(f"SSL Issuer: {ssl_info.get('issuer', {}).get('O', 'N/A')}, Valid Until: {ssl_info.get('notAfter', 'N/A')}")

    # Content Analysis
    content_analysis = url_data.get('content_analysis', {})
    summary.append(f"Title: {content_analysis.get('title', 'N/A')}")
    summary.append(f"Links: {len(content_analysis.get('links', []))}, Forms: {len(content_analysis.get('forms', []))}")
    summary.append(f"Login Form: {'Present' if content_analysis.get('has_login_form') else 'Absent'}")

    # JavaScript Analysis
    js_analysis = url_data.get('javascript_analysis', {})
    summary.append(f"Scripts: {js_analysis.get('script_count', 'N/A')}, Suspicious: {len(js_analysis.get('suspicious_scripts', []))}")

    return "\n".join(summary)

def generate_prompt(url: str, url_data: Dict[str, Any]) -> str:
    summary = summarize_url_data(url_data)
    
    prompt = f"""URL Threat Analysis Task

Target URL: {url}

Summary Information:
{summary}

Perform the following tasks to assess the potential threat of this URL. Each task is crucial in determining the safety and trustworthiness of the URL.

1. URL Classification
Purpose: Quickly assess the overall risk level of the URL.
Instruction: Classify into one of the following and briefly explain why.
Response format: Classification: [Legitimate/Suspicious/Phishing] - Reason: [Brief explanation]

2. URL Structure Analysis
Purpose: Analyze the URL components in detail to identify suspicious patterns.
Instruction: Analyze the following three aspects:
a) Domain and brand relationship
b) URL complexity and patterns
c) TLD (Top-Level Domain) assessment
Response format: Provide one sentence of analysis for each aspect.

3. Key Findings
Purpose: Provide core information about the legitimacy or phishing potential of the URL.
Instruction: List the three most important findings.
Response format: Numbered list with one sentence explanation for each finding.

4. Phishing Likelihood Assessment
Purpose: Evaluate the phishing risk based on comprehensive analysis.
Instruction: Assess the likelihood of phishing as low, medium, or high and explain why.
Response format: Phishing likelihood: [Low/Medium/High] - Reason: [Brief explanation]

5. Security Recommendation
Purpose: Provide necessary precautions for users when dealing with this URL.
Instruction: Present specific recommendations for safe use or avoidance of the URL.
Response format: Provide clear recommendations in one or two sentences.

Provide concise and clear responses for each task. Base your analysis on the provided summary information and avoid unnecessary speculation.
"""
    
    return prompt

if __name__ == "__main__":
    url = "https://www.naver.com"  # 테스트할 URL을 여기에 입력하세요
    url_data = get_url_content(url)
    prompt = generate_prompt(url, url_data)
    print(prompt)