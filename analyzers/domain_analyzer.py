from typing import Dict, Optional, List, Any
import whois
import dns.resolver
from functools import lru_cache
from urllib.parse import urlparse
import logging
from utils.config import DomainInfo  # 추가

logger = logging.getLogger(__name__)

class DomainAnalyzer:
    def __init__(self, config):
        self.config = config
        # whois 타임아웃 설정
        whois.socket.setdefaulttimeout(5)  # 5초로 제한
        self.logger = logging.getLogger(__name__)

    @lru_cache(maxsize=100)
    def analyze_domain(self, url: str) -> Dict[str, Optional[str]]:
        parsed = urlparse(url)
        return {
            'domain': parsed.netloc,
            'tld': parsed.netloc.split('.')[-1],
            'subdomain': '.'.join(parsed.netloc.split('.')[:-2]) if len(parsed.netloc.split('.')) > 2 else None
        }

    def get_whois_info(self, domain: str) -> Dict[str, Any]:
        try:
            w = whois.whois(domain)
            return {
                "registrar": w.registrar,
                "creation_date": w.creation_date,
                "expiration_date": w.expiration_date,
                "name_servers": w.name_servers
            }
        except Exception as e:
            self.logger.error(f"WHOIS error for {domain}: {str(e)}")
            return {"error": str(e)}

    def get_dns_records(self, domain: str) -> Dict[str, Dict[str, Any]]:
        records = {}
        for record_type in ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records[record_type] = {
                    "status": "found",
                    "records": [str(rdata) for rdata in answers],
                    "count": len(answers)
                }
            except dns.resolver.NoAnswer:
                records[record_type] = {
                    "status": "no_records",
                    "records": [],
                    "count": 0
                }
            except dns.resolver.NXDOMAIN:
                records[record_type] = {
                    "status": "domain_not_found",
                    "records": [],
                    "count": 0
                }
            except Exception as e:
                records[record_type] = {
                    "status": "error",
                    "records": [],
                    "count": 0,
                    "error": str(e)
                }
        
        records["analysis"] = {
            "uses_multiple_a_records": len(records.get("A", {}).get("records", [])) > 1,
            "has_ipv6": len(records.get("AAAA", {}).get("records", [])) > 0,
            "has_mx": len(records.get("MX", {}).get("records", [])) > 0,
            "has_txt": len(records.get("TXT", {}).get("records", [])) > 0,
            "total_records": sum(r.get("count", 0) for r in records.values() if isinstance(r, dict))
        }
        
        return records
