from typing import Dict, Any
import ssl
import socket
import requests
import re
import logging
from utils.config import SecurityInfo  # 추가

logger = logging.getLogger(__name__)

class SecurityAnalyzer:
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)

    def get_ssl_info(self, domain: str) -> Dict[str, Any]:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                    cert = secure_sock.getpeercert()
            return {
                "issuer": dict(x[0] for x in cert['issuer']),
                "notAfter": cert['notAfter'],
                "notBefore": cert['notBefore'],
                "subject": dict(x[0] for x in cert['subject'])
            }
        except Exception as e:
            self.logger.error(f"SSL error for {domain}: {str(e)}")
            return {"error": str(e)}

    def analyze_headers(self, url: str) -> Dict[str, str]:
        try:
            response = requests.head(url, timeout=self.config.timeout)
            return dict(response.headers)
        except Exception as e:
            self.logger.error(f"Headers error for {url}: {str(e)}")
            return {"error": str(e)}

    def check_security_features(self, headers: Dict[str, str]) -> Dict[str, Any]:
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        return {
            "has_hsts": any(h for h in headers_lower.keys() if 'strict-transport-security' in h),
            "has_csp": any(h for h in headers_lower.keys() if 'content-security-policy' in h),
            "has_xframe": any(h for h in headers_lower.keys() if 'x-frame-options' in h),
            "has_xss_protection": any(h for h in headers_lower.keys() if 'x-xss-protection' in h),
            "is_hsts_valid": bool(re.search(r'max-age=\d+', headers_lower.get('strict-transport-security', ''))),
            "xframe_policy": headers_lower.get('x-frame-options', 'Not Set').upper(),
            "xss_protection_mode": headers_lower.get('x-xss-protection', 'Not Set')
        }