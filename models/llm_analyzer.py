from typing import Dict, Any, Optional, Tuple, List
from dataclasses import dataclass
import torch
import transformers
from transformers import AutoModelForCausalLM, AutoTokenizer
from transformers import BitsAndBytesConfig
import re
import logging
from utils.config import Config

logger = logging.getLogger(__name__)
@dataclass
class LLMResponse:
    text: str
    total_tokens: int
    raw_response: str

@dataclass
class Finding:
    title: str
    detail: str

class LLMAnalyzer:
    def __init__(self, config: Config):
        self.config = config
        self.device = self._setup_device()
        self.model = None
        self.tokenizer = None
        self.pipeline = None
        
        # XML 태그 파싱을 위한 정규식 패턴
        self.patterns = {
            'classification': r'<classification>\s*status:\s*([^\n]+)\s*reason:\s*([^\n]+)\s*</classification>',
            'security_assessment': r'<security_assessment>\s*ssl:\s*([^\n]+)\s*headers:\s*([^\n]+)\s*content:\s*([^\n]+)\s*</security_assessment>',
            'findings': r'<findings>\s*((?:(?:\d+\.\s*title:[^\n]+\s*detail:[^\n]+\s*)+))</findings>',
            'risk_assessment': r'<risk_assessment>\s*level:\s*([^\n]+)\s*reason:\s*([^\n]+)\s*</risk_assessment>',
            'recommendations': r'<recommendations>\s*((?:\d+\.\s*[^\n]+\s*)+)</recommendations>'
        }

    def _setup_device(self) -> torch.device:
        """GPU/CPU 디바이스 설정"""
        if torch.cuda.is_available():
            device = torch.device("cuda")
        else:
            device = torch.device("cpu")
        logger.info(f"Using device: {device}")
        return device

    def load_model(self) -> Optional[transformers.Pipeline]:
        """모델 및 토크나이저 로드"""
        if self.pipeline is not None:
            return self.pipeline

        try:
            self.tokenizer = AutoTokenizer.from_pretrained(
                self.config.model_id,
                trust_remote_code=True,
                use_fast=True
            )
            
            if self.device.type == "cuda":
                quantization_config = BitsAndBytesConfig(
                    load_in_8bit=True,
                    llm_int8_threshold=6.0,
                    llm_int8_has_fp16_weight=False,
                    llm_int8_enable_fp32_cpu_offload=True
                )
                
                self.model = AutoModelForCausalLM.from_pretrained(
                    self.config.model_id,
                    quantization_config=quantization_config,
                    device_map="auto",
                    torch_dtype=torch.float16,
                    low_cpu_mem_usage=True,
                    trust_remote_code=True
                )
            else:
                self.model = AutoModelForCausalLM.from_pretrained(
                    self.config.model_id,
                    device_map={"": self.device},
                    low_cpu_mem_usage=True,
                    trust_remote_code=True
                )
            
            self.pipeline = transformers.pipeline(
                "text-generation",
                model=self.model,
                tokenizer=self.tokenizer,
                device_map="auto"
            )
            
            return self.pipeline
            
        except Exception as e:
            logger.error(f"모델 로딩 중 오류 발생: {e}")
            return None

    def generate_analysis(self, prompt: str) -> Tuple[str, int, str]:
        """LLM 분석 수행 및 결과 반환"""
        try:
            llm_response = self._generate_analysis(prompt)
            return llm_response.text, llm_response.total_tokens, llm_response.raw_response

        except Exception as e:
            logger.error(f"Failed to generate analysis: {str(e)}")
            raise

    def _generate_analysis(self, prompt: str) -> LLMResponse:
        """LLM을 사용하여 분석 생성"""
        try:
            pipeline = self.load_model()
            if pipeline is None:
                raise Exception("Failed to load model")

            with torch.no_grad():
                result = pipeline(
                    prompt,
                    max_new_tokens=self.config.max_tokens,
                    do_sample=True,
                    temperature=self.config.temperature,
                    top_p=self.config.top_p,
                    num_return_sequences=1,
                    eos_token_id=pipeline.tokenizer.eos_token_id,
                    pad_token_id=pipeline.tokenizer.eos_token_id,
                    remove_invalid_values=True
                )

            generated_text = result[0]['generated_text']
            response = generated_text.split(prompt)[-1].strip()
            total_tokens = len(pipeline.tokenizer.encode(response))
            
            return LLMResponse(
                text=response,
                total_tokens=total_tokens,
                raw_response=generated_text
            )

        except RuntimeError as e:
            if "out of memory" in str(e):
                logger.warning("CUDA out of memory. Switching to CPU...")
                if self.device.type == "cuda":
                    self.cleanup()
                    self.device = torch.device("cpu")
                    return self._generate_analysis(prompt)
            raise

    def parse_response(self, response: str) -> Dict[str, Any]:
        """LLM 응답 파싱"""
        try:
            class_match = re.search(self.patterns['classification'], response, re.DOTALL)
            security_match = re.search(self.patterns['security_assessment'], response, re.DOTALL)
            findings_match = re.search(self.patterns['findings'], response, re.DOTALL)
            risk_match = re.search(self.patterns['risk_assessment'], response, re.DOTALL)
            recom_match = re.search(self.patterns['recommendations'], response, re.DOTALL)

            if not all([class_match, security_match, risk_match]):
                raise ValueError("Required sections missing in response")

            findings = []
            if findings_match:
                findings_text = findings_match.group(1)
                finding_pattern = r'(\d+)\.\s*title:\s*([^\n]+)\s*detail:\s*([^\n]+)'
                findings = [
                    f"{m.group(2).strip()}: {m.group(3).strip()}"
                    for m in re.finditer(finding_pattern, findings_text)
                ]

            recommendations = []
            if recom_match:
                recom_text = recom_match.group(1)
                recommendations = [
                    rec.strip()
                    for rec in re.findall(r'\d+\.\s*([^\n]+)', recom_text)
                ]

            return {
                "classification": f"{class_match.group(1).strip()} - {class_match.group(2).strip()}",
                "security_assessment": [
                    security_match.group(1).strip(),
                    security_match.group(2).strip(),
                    security_match.group(3).strip()
                ],
                "key_findings": findings,
                "risk_assessment": f"{risk_match.group(1).strip()} - {risk_match.group(2).strip()}",
                "technical_recommendations": recommendations
            }
            
        except Exception as e:
            logger.error(f"응답 파싱 중 오류 발생: {e}")
            logger.debug(f"Raw response: {response}")
            return {
                "classification": f"ERROR - {str(e)}",
                "security_assessment": ["Error parsing response"],
                "key_findings": [],
                "risk_assessment": "ERROR",
                "technical_recommendations": []
            }

    def format_analysis_result(self, result: Dict[str, Any]) -> str:
        """분석 결과를 포맷팅"""
        try:
            formatted_output = f"""
URL Security Analysis Report
{'='*50}

Classification: {result['classification']}

Security Assessment:
"""
            for assessment in result['security_assessment']:
                formatted_output += f"- {assessment}\n"
            
            formatted_output += "\nKey Technical Findings:"
            for i, finding in enumerate(result['key_findings'], 1):
                formatted_output += f"\n{i}. {finding}"
            
            formatted_output += f"\n\nRisk Assessment: {result['risk_assessment']}\n"
            
            formatted_output += "\nTechnical Recommendations:"
            for i, rec in enumerate(result['technical_recommendations'], 1):
                formatted_output += f"\n{i}. {rec}"
            
            return formatted_output
            
        except Exception as e:
            logger.error(f"결과 포맷팅 중 오류 발생: {e}")
            return f"Error formatting results: {str(e)}"

    def cleanup(self):
        """리소스 정리"""
        try:
            if self.device.type == "cuda":
                torch.cuda.empty_cache()
            
            self.model = None
            self.tokenizer = None
            self.pipeline = None
            
            logger.info("Successfully cleaned up resources")
            
        except Exception as e:
            logger.error(f"리소스 정리 중 오류 발생: {e}")