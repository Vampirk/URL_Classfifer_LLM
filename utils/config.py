# utils/config.py

from dataclasses import dataclass, field
from typing import Dict, Optional, List, Any

@dataclass
class Config:
    # 일반 설정
    timeout: int = 10
    max_retries: int = 3
    retry_delay: int = 5
    max_workers: int = 5
    cache_size: int = 100
    
    # HTTP 요청 설정
    user_agent: str = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    headers: Dict[str, str] = field(default_factory=dict)
    
    # LLM 설정
    model_id: str = "Meta-Llama-3.1-8B-Instruct"
    max_tokens: int = 550
    temperature: float = 0.7
    top_p: float = 0.95
    
    def __post_init__(self):
        if not self.headers:
            self.headers = {
                'User-Agent': self.user_agent
            }

@dataclass
class DomainInfo:
    domain: str
    tld: str
    subdomain: Optional[str]
    whois_info: Dict
    dns_records: Dict

@dataclass
class SecurityInfo:
    ssl_certificate: Dict
    headers: Dict
    security_features: Dict

@dataclass
class ContentInfo:
    title: Optional[str]
    meta_tags: Dict
    links: List[str]
    forms: List[Dict]
    javascript_info: Dict
    content_analysis: Dict
    external_resources: List[str]
    has_login_form: bool

@dataclass
class AnalysisResult:
    domain_info: DomainInfo
    security_info: SecurityInfo
    content_info: ContentInfo
    url_structure: Dict
    raw_html: Optional[str] = None