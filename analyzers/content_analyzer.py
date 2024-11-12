from typing import Dict, Any
from bs4 import BeautifulSoup
import re
from collections import Counter
import statistics
import logging
from urllib.parse import urlparse
from utils.config import ContentInfo  # 추가

logger = logging.getLogger(__name__)

class ContentAnalyzer:
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)

    def analyze_html(self, url: str, content: str) -> Dict[str, Any]:
        soup = BeautifulSoup(content, 'html.parser')
        
        return {
            'title': soup.title.string if soup.title else None,
            'meta_tags': {meta.get('name'): meta.get('content') 
                        for meta in soup.find_all('meta') if meta.get('name')},
            'links': [link.get('href') for link in soup.find_all('a')],
            'forms': [{'action': form.get('action'), 'method': form.get('method')} 
                    for form in soup.find_all('form')],
            'external_resources': [src.get('src') 
                                for src in soup.find_all(['img', 'script', 'iframe', 'link']) 
                                if src.get('src') and src.get('src').startswith('http')],
            'has_login_form': bool(soup.find('form', {'action': re.compile(r'login|signin', re.I)})),
            'content_analysis': {}  # 추가 분석을 위한 빈 딕셔너리
        }

    def analyze_javascript(self, content: str) -> Dict[str, Any]:
        scripts = re.findall(r'<script\b[^>]*>(.*?)</script>', content, re.DOTALL)
        external_scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)', content)
        
        suspicious_patterns = {
            "eval_usage": r'eval\s*\(',
            "document_write": r'document\.write\s*\(',
            "cookie_manipulation": r'document\.cookie',
            "location_manipulation": r'(?:window|document|top)\.location',
            "dangerous_functions": r'(?:fromCharCode|escape|unescape|atob|btoa)',
            "inline_events": r'on(?:error|load|click|mouseover|submit)\s*=',
            "data_uri": r'data:(?:text|application)/javascript',
            "base64_usage": r'base64',
            "iframe_dynamic": r'createElement\s*\(\s*[\'"]iframe[\'"]',
            "xhr_requests": r'(?:XMLHttpRequest|fetch|ajax)',
            "local_storage": r'localStorage',
            "session_storage": r'sessionStorage',
            "dom_modification": r'(?:innerHTML|outerHTML)\s*='
        }
        
        resource_patterns = {
            "script_load": r'(?:loadScript|getScript)',
            "dynamic_import": r'import\s*\(',
            "require_usage": r'require\s*\(',
            "dynamic_css": r'(?:link|style)\.(?:href|cssText)'
        }
        
        analysis = {
            "script_count": len(scripts),
            "external_script_count": len(external_scripts),
            "inline_script_count": len([s for s in scripts if s.strip()]),
            "suspicious_patterns": {
                pattern: bool(any(re.search(regex, script) for script in scripts))
                for pattern, regex in suspicious_patterns.items()
            },
            "resource_patterns": {
                pattern: bool(any(re.search(regex, script) for script in scripts))
                for pattern, regex in resource_patterns.items()
            },
            "external_scripts": {
                "all": external_scripts,
                "domains": list(set([urlparse(src).netloc for src in external_scripts if src.startswith('http')])),
                "count_by_domain": dict(Counter([urlparse(src).netloc 
                                               for src in external_scripts 
                                               if src.startswith('http')]))
            },
            "script_sizes": {
                "total_inline_length": sum(len(s) for s in scripts if s.strip()),
                "average_inline_length": statistics.mean([len(s) for s in scripts if s.strip()]) if scripts else 0,
                "max_inline_length": max([len(s) for s in scripts if s.strip()], default=0)
            }
        }
        
        risk_factors = [
            analysis["suspicious_patterns"]["eval_usage"],
            analysis["suspicious_patterns"]["document_write"],
            analysis["suspicious_patterns"]["dangerous_functions"],
            bool(analysis["external_scripts"]["count_by_domain"]),
            analysis["suspicious_patterns"]["iframe_dynamic"],
            analysis["suspicious_patterns"]["data_uri"]
        ]
        
        analysis["risk_assessment"] = {
            "score": sum(risk_factors) / len(risk_factors) * 10,
            "risk_level": "High" if sum(risk_factors) > 3 else "Medium" if sum(risk_factors) > 1 else "Low"
        }
        
        return analysis