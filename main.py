import logging
from typing import Dict, Any, Optional
import torch
from urllib.parse import urlparse
import re
import concurrent.futures
import time
import requests
from urllib.parse import parse_qs

from utils.config import (
    Config, 
    AnalysisResult,
    DomainInfo,     # 추가
    SecurityInfo,   # 추가
    ContentInfo     # 추가
)
from analyzers.domain_analyzer import DomainAnalyzer
from analyzers.security_analyzer import SecurityAnalyzer
from analyzers.content_analyzer import ContentAnalyzer
from models.llm_analyzer import LLMAnalyzer
from utils.prompt_generator import generate_prompt

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class URLSecurityAnalyzer:
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        
        # 각 분석기 초기화
        self.domain_analyzer = DomainAnalyzer(self.config)
        self.security_analyzer = SecurityAnalyzer(self.config)
        self.content_analyzer = ContentAnalyzer(self.config)
        self.llm_analyzer = LLMAnalyzer(self.config)

    def analyze_url_structure(self, url: str) -> Dict[str, Any]:
        parsed = urlparse(url)
        return {
            'length': len(url),
            'ip_in_url': bool(re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', url)),
            'abnormal_chars': bool(re.search(r'[^a-zA-Z0-9-._~:/?#\[\]@!$&\'()*+,;%=]', url)),
            'num_params': len(parse_qs(parsed.query))
        }

    def _get_url_content(self, url: str) -> Optional[requests.Response]:
        for attempt in range(self.config.max_retries):
            try:
                response = requests.get(url, headers=self.config.headers, timeout=self.config.timeout)
                if response.status_code == 200:
                    return response
                
                logger.warning(f"Received status code {response.status_code} from {url}")
                if attempt < self.config.max_retries - 1:
                    time.sleep(self.config.retry_delay)
                    
            except Exception as e:
                logger.warning(f"Attempt {attempt + 1} failed for {url}: {str(e)}")
                if attempt < self.config.max_retries - 1:
                    time.sleep(self.config.retry_delay)
                else:
                    raise
        
        return None

    def analyze(self, url: str) -> Dict[str, Any]:
        try:
            # URL 콘텐츠 가져오기
            response = self._get_url_content(url)
            content = response.text if response else None
            domain = urlparse(url).netloc

            # 병렬 분석 실행
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
                domain_future = executor.submit(self.domain_analyzer.analyze_domain, url)
                whois_future = executor.submit(self.domain_analyzer.get_whois_info, domain)
                dns_future = executor.submit(self.domain_analyzer.get_dns_records, domain)
                ssl_future = executor.submit(self.security_analyzer.get_ssl_info, domain)
                headers_future = executor.submit(self.security_analyzer.analyze_headers, url)

            # 결과 수집
            domain_info = DomainInfo(
                **domain_future.result(),
                whois_info=whois_future.result(),
                dns_records=dns_future.result()
            )

            headers = headers_future.result()
            security_info = SecurityInfo(
                ssl_certificate=ssl_future.result(),
                headers=headers,
                security_features=self.security_analyzer.check_security_features(headers)
            )

            # 콘텐츠 분석
            if content:
                html_analysis = self.content_analyzer.analyze_html(url, content)
                js_analysis = self.content_analyzer.analyze_javascript(content)
                
                content_info = ContentInfo(
                    **html_analysis,
                    javascript_info=js_analysis
                )
            else:
                content_info = ContentInfo(
                    title=None,
                    meta_tags={},
                    links=[],
                    forms=[],
                    external_resources=[],
                    has_login_form=False,
                    javascript_info={},
                    content_analysis={}
                )

            # 최종 분석 결과 생성
            analysis_result = AnalysisResult(
                domain_info=domain_info,
                security_info=security_info,
                content_info=content_info,
                url_structure=self.analyze_url_structure(url),
                raw_html=content
            )

            # LLM 분석 수행
            prompt = generate_prompt(url, analysis_result)
            response, tokens, full_text = self.llm_analyzer.generate_analysis(prompt)
            llm_analysis = self.llm_analyzer.parse_response(response)

            # 결과 통합
            final_result = {
                "url": url,
                "technical_analysis": analysis_result,
                "llm_analysis": llm_analysis,
                "tokens_used": tokens,
                "full_llm_response": full_text
            }

            return final_result

        except Exception as e:
            logger.error(f"Analysis failed for {url}: {str(e)}")
            return {"url": url, "error": str(e)}

    def print_analysis_report(self, result: Dict[str, Any]):
        if "error" in result:
            print(f"\nError analyzing URL: {result['error']}")
            return

        print("\n=== Technical Analysis Report ===")
        analysis = result["technical_analysis"]
        
        print("\n1. Domain Information:")
        print(f"   Domain: {analysis.domain_info.domain}")
        print(f"   Created: {analysis.domain_info.whois_info.get('creation_date')}")
        print(f"   Registrar: {analysis.domain_info.whois_info.get('registrar')}")
        
        print("\n2. Security Status:")
        print(f"   SSL Valid Until: {analysis.security_info.ssl_certificate.get('notAfter')}")
        print("   Security Features:")
        for feature, status in analysis.security_info.security_features.items():
            print(f"   - {feature}: {status}")
        
        print("\n3. Content Analysis:")
        print(f"   Title: {analysis.content_info.title}")
        print(f"   External Resources: {len(analysis.content_info.external_resources)}")
        print(f"   JavaScript Risk Level: {analysis.content_info.javascript_info.get('risk_assessment', {}).get('risk_level')}")

        print("\n=== LLM Analysis Report ===")
        print(self.llm_analyzer.format_analysis_result(result["llm_analysis"]))
        
        print("\n=== Analysis Statistics ===")
        print(f"Tokens Used: {result['tokens_used']}")

def main():
    import argparse
    parser = argparse.ArgumentParser(description='Analyze URL security')
    parser.add_argument('url', help='URL to analyze')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout')
    parser.add_argument('--max-retries', type=int, default=3, help='Maximum retry attempts')
    args = parser.parse_args()

    # 설정 초기화
    config = Config(
        timeout=args.timeout,
        max_retries=args.max_retries
    )

    # 분석기 초기화 및 실행
    analyzer = URLSecurityAnalyzer(config)
    try:
        result = analyzer.analyze(args.url)
        analyzer.print_analysis_report(result)
        
        # GPU 사용 정보 출력
        if torch.cuda.is_available():
            print("\nGPU Memory Usage:")
            print(f"Allocated: {torch.cuda.memory_allocated()/1e9:.2f} GB")
            print(f"Reserved: {torch.cuda.memory_reserved()/1e9:.2f} GB")
            
    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}")

if __name__ == "__main__":
    main()