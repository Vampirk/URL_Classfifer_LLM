import torch
import transformers
from transformers import AutoModelForCausalLM, AutoTokenizer
from transformers import BitsAndBytesConfig
import re
from typing import List, Dict, Optional, Any, Tuple
from url_analysis_utils import get_url_content, generate_prompt
import os
import logging

# 로깅 설정
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 환경 변수 설정
os.environ['PYTORCH_CUDA_ALLOC_CONF'] = 'max_split_size_mb:128'

MODEL_ID = "Meta-Llama-3.1-8B-Instruct"  # 필요하다면 더 작은 모델로 변경
model = None
tokenizer = None

def setup_device() -> torch.device:
    if torch.cuda.is_available():
        device = torch.device("cuda")
        # GPU 메모리 제한 설정
        torch.cuda.set_per_process_memory_fraction(0.8)  # GPU 메모리의 80%만 사용
    else:
        device = torch.device("cpu")
    logger.info(f"Using device: {device}")
    return device

def load_model(device: torch.device) -> Optional[transformers.Pipeline]:
    global model, tokenizer
    if model is None:
        try:
            # 토크나이저 로드
            tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
            
            if device.type == "cuda":
                # GPU용 8-bit 양자화 설정
                quantization_config = BitsAndBytesConfig(
                    load_in_8bit=True,
                    llm_int8_threshold=6.0,
                    llm_int8_has_fp16_weight=False,
                )
                
                # 모델 로드 (8-bit 양자화 적용)
                model = AutoModelForCausalLM.from_pretrained(
                    MODEL_ID,
                    quantization_config=quantization_config,
                    device_map="auto",
                    torch_dtype=torch.float16,
                    low_cpu_mem_usage=True,
                )
            else:
                # CPU용 설정
                model = AutoModelForCausalLM.from_pretrained(
                    MODEL_ID,
                    device_map={"": device},
                    low_cpu_mem_usage=True,
                )
            
            # 파이프라인 생성
            pipeline = transformers.pipeline(
                "text-generation",
                model=model,
                tokenizer=tokenizer,
                device_map={"": device},
            )
            
            return pipeline
        except Exception as e:
            logger.error(f"모델 로딩 중 오류 발생: {e}")
            return None
    else:
        return transformers.pipeline(
            "text-generation",
            model=model,
            tokenizer=tokenizer,
            device_map={"": device},
        )

def generate_analysis(pipeline, prompt: str, max_tokens: int = 500) -> Tuple[str, int, str]:
    try:
        with torch.no_grad():
            result = pipeline(
                prompt,
                max_new_tokens=max_tokens,
                do_sample=True,
                temperature=0.7,
                top_p=0.95,
                num_return_sequences=1,
                eos_token_id=pipeline.tokenizer.eos_token_id,
                pad_token_id=pipeline.tokenizer.eos_token_id,
            )
        generated_text = result[0]['generated_text']
        response = generated_text.split(prompt)[-1].strip()
        total_tokens = len(pipeline.tokenizer.encode(response))
        
        # Log the full generated text for debugging
        logger.debug(f"Full generated text:\n{generated_text}")
        
        return response, total_tokens, generated_text
    except RuntimeError as e:
        if "out of memory" in str(e):
            logger.warning("CUDA out of memory. Switching to CPU...")
            pipeline.device = torch.device("cpu")
            pipeline.model.to("cpu")
            return generate_analysis(pipeline, prompt, max_tokens)
        else:
            raise e

def parse_response(response: str) -> Dict[str, Any]:
    parsed_result = {
        "classification": "N/A",
        "url_analysis": [],
        "key_findings": [],
        "phishing_likelihood": "N/A",
        "security_recommendation": "N/A"
    }
    
    # 섹션 분리
    sections = re.split(r'\*\*Task \d+:|={10,}', response)
    
    for section in sections:
        if "URL Classification" in section:
            match = re.search(r'Classification:\s*(\w+)\s*-\s*Reason:\s*(.+)', section, re.DOTALL)
            if match:
                parsed_result["classification"] = f"{match.group(1)} - {match.group(2).strip()}"
        elif "URL Structure Analysis" in section:
            parsed_result["url_analysis"] = re.findall(r'^[a-c]\)(.+)$', section, re.MULTILINE)
        elif "Key Findings" in section:
            parsed_result["key_findings"] = re.findall(r'^\d+\.\s*(.+)$', section, re.MULTILINE)
        elif "Phishing Likelihood Assessment" in section:
            match = re.search(r'Phishing likelihood:\s*(\w+)\s*-\s*Reason:\s*(.+)', section, re.DOTALL)
            if match:
                parsed_result["phishing_likelihood"] = f"{match.group(1)} - {match.group(2).strip()}"
        elif "Security Recommendation" in section:
            parsed_result["security_recommendation"] = section.split("Response format:")[-1].strip()
    
    return parsed_result

def analyze_url(url: str, pipeline, url_data: Dict[str, Any], max_tokens: int = 500) -> Dict[str, Any]:
    try:
        prompt = generate_prompt(url, url_data)
        logger.debug(f"Generated prompt:\n{prompt}")
        
        response, total_tokens, full_generated_text = generate_analysis(pipeline, prompt, max_tokens)
        logger.debug(f"Model response:\n{response}")
        
        parsed_result = parse_response(response)
        parsed_result["url"] = url
        parsed_result["analysis_length"] = total_tokens
        parsed_result["full_generated_text"] = full_generated_text  # Add this for debugging
        return parsed_result
    except Exception as e:
        logger.error(f"Error in analyze_url: {str(e)}")
        return {"url": url, "error": str(e)}

def format_result(result: Dict[str, Any]) -> str:
    formatted_output = f"""
URL: {result.get('url', 'N/A')}
{'='*50}
Classification: {result.get('classification', 'N/A')}
{'='*50}
URL Analysis:
"""
    for point in result.get('url_analysis', []):
        formatted_output += f"- {point}\n"
    
    formatted_output += f"""
{'='*50}
Key Findings:
"""
    for point in result.get('key_findings', []):
        formatted_output += f"- {point}\n"
    
    formatted_output += f"""
{'='*50}
Phishing Likelihood: {result.get('phishing_likelihood', 'N/A')}
{'='*50}
Security Recommendation: {result.get('security_recommendation', 'N/A')}
{'='*50}
Analysis Length: {result.get('analysis_length', 'N/A')} tokens
"""
    
    if 'error' in result:
        formatted_output += f"Error: {result['error']}\n"
    
    # Add full generated text for debugging
    formatted_output += f"""
{'='*50}
Full Generated Text (for debugging):
{result.get('full_generated_text', 'N/A')}
"""
    
    return formatted_output

def classify_url(url: str, max_tokens: int = 500) -> Dict[str, Any]:
    device = setup_device()
    pipeline = load_model(device)
    if pipeline is None:
        return {"url": url, "error": "Failed to load model"}
    
    try:
        url_data = get_url_content(url)
        result = analyze_url(url, pipeline, url_data, max_tokens)
        if device.type == "cuda":
            torch.cuda.empty_cache()
        return result
    except Exception as e:
        logger.error(f"Error analyzing URL ({url}): {str(e)}")
        return {"url": url, "error": str(e)}

def print_gpu_memory():
    if torch.cuda.is_available():
        logger.info(f"GPU memory allocated: {torch.cuda.memory_allocated()/1e9:.2f} GB")
        logger.info(f"GPU memory reserved: {torch.cuda.memory_reserved()/1e9:.2f} GB")

def main():
    url = "https://www.google.com"  # Replace with the URL you want to analyze
    result = classify_url(url)
    print("\nAnalysis Result:")
    print("="*50)
    print(format_result(result))
    
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    if device.type == "cuda":
        print("\nGPU memory usage:")
        print_gpu_memory()

if __name__ == "__main__":
    main()