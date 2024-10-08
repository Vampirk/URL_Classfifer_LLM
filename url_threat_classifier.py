import torch
import transformers
import re
from typing import List, Dict, Optional
from url_analysis_utils import get_url_content, generate_prompt

MODEL_ID = "Meta-Llama-3.1-8B-Instruct"
pipeline = None

def setup_device() -> torch.device:
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Using device: {device}")
    return device

def load_model() -> Optional[transformers.Pipeline]:
    global pipeline
    if pipeline is None:
        try:
            pipeline = transformers.pipeline(
                "text-generation",
                model=MODEL_ID,
                model_kwargs={"torch_dtype": torch.bfloat16},
                device_map="auto",
            )
        except Exception as e:
            print(f"모델 로딩 중 오류 발생: {e}")
            return None
    return pipeline

def generate_analysis(pipeline, prompt: str, target_length: int = 1024, max_attempts: int = 5) -> str:
    full_response = ""
    for attempt in range(max_attempts):
        result = pipeline(
            prompt,
            max_new_tokens=target_length,
            do_sample=True,
            temperature=0.4,
            top_p=0.92,
            num_return_sequences=1,
            repetition_penalty=1.1,
            eos_token_id=pipeline.tokenizer.eos_token_id,
            pad_token_id=pipeline.tokenizer.eos_token_id,
        )
        generated_text = result[0]['generated_text']
        response = generated_text.split("Provide your analysis below:")[1].strip()
        full_response += response

        if len(pipeline.tokenizer.encode(full_response)) >= target_length:
            break
        elif "Conclusion:" in response:
            remaining_tokens = target_length - len(pipeline.tokenizer.encode(full_response))
            if remaining_tokens > 50:
                prompt = f"{prompt}\n{full_response}\nContinue the analysis to reach approximately {remaining_tokens} more tokens:"
            else:
                break
        else:
            prompt = f"{prompt}\n{full_response}\nContinue the analysis:"

    return full_response

def parse_response(response: str) -> Dict[str, Optional[str]]:
    parsed_result = {
        "classification": None,
        "suspicion_level": None,
        "url_analysis": [],
        "content_analysis": [],
        "overall_assessment": [],
        "safety": None,
        "key_findings": None,
        "recommendation": None
    }
    
    classification_match = re.search(r"Classification:\s*(\w+)", response)
    if classification_match:
        parsed_result["classification"] = classification_match.group(1)
    
    suspicion_level_match = re.search(r"Suspicion Level:\s*(\d+)", response)
    if suspicion_level_match:
        parsed_result["suspicion_level"] = suspicion_level_match.group(1)
    
    url_analysis_matches = re.findall(r"URL Analysis:(.+?)Content Analysis:", response, re.DOTALL)
    if url_analysis_matches:
        parsed_result["url_analysis"] = re.findall(r"\d+\.\s*(.+)", url_analysis_matches[0])
    
    content_analysis_matches = re.findall(r"Content Analysis:(.+?)Overall Assessment:", response, re.DOTALL)
    if content_analysis_matches:
        parsed_result["content_analysis"] = re.findall(r"\d+\.\s*(.+)", content_analysis_matches[0])
    
    overall_assessment_matches = re.findall(r"Overall Assessment:(.+?)Conclusion:", response, re.DOTALL)
    if overall_assessment_matches:
        parsed_result["overall_assessment"] = re.findall(r"\d+\.\s*(.+)", overall_assessment_matches[0])
    
    safety_match = re.search(r"Safety:\s*(.+)", response)
    if safety_match:
        parsed_result["safety"] = safety_match.group(1)
    
    key_findings_match = re.search(r"Key Findings:\s*(.+)", response)
    if key_findings_match:
        parsed_result["key_findings"] = key_findings_match.group(1)
    
    recommendation_match = re.search(r"Recommendation:\s*(.+)", response)
    if recommendation_match:
        parsed_result["recommendation"] = recommendation_match.group(1)
    
    return parsed_result

def analyze_url(url: str, pipeline, url_data: Dict[str, str], analysis_length: int = 1024) -> Dict[str, str]:
    prompt = generate_prompt(url, url_data)
    try:
        full_response = generate_analysis(pipeline, prompt, target_length=analysis_length)
        parsed_result = parse_response(full_response)
        parsed_result["url"] = url
        parsed_result["analysis_length"] = len(pipeline.tokenizer.encode(full_response))
        return parsed_result
    except Exception as e:
        return {"url": url, "error": str(e)}

def classify_urls(urls: List[str], analysis_length: int = 1024) -> List[Dict[str, str]]:
    pipeline = load_model()
    if pipeline is None:
        return [{"error": "모델 로딩 실패"} for _ in urls]
    
    results = []
    for url in urls:
        url_data = get_url_content(url)
        result = analyze_url(url, pipeline, url_data, analysis_length=analysis_length)
        results.append(result)
    
    return results

def print_gpu_memory():
    if torch.cuda.is_available():
        print(f"GPU memory allocated: {torch.cuda.memory_allocated()/1e9:.2f} GB")
        print(f"GPU memory reserved: {torch.cuda.memory_reserved()/1e9:.2f} GB")

def format_result(result: Dict[str, str]) -> str:
    formatted_output = f"""
URL: {result['url']}
{'='*50}
Classification: {result['classification']}
Suspicion Level: {result['suspicion_level']}
{'='*50}
URL Analysis:
"""
    for point in result['url_analysis']:
        formatted_output += f"- {point}\n"
    
    formatted_output += f"\nContent Analysis:\n"
    for point in result['content_analysis']:
        formatted_output += f"- {point}\n"
    
    formatted_output += f"\nOverall Assessment:\n"
    for point in result['overall_assessment']:
        formatted_output += f"- {point}\n"
    
    formatted_output += f"""
{'='*50}
Conclusion:
Safety: {result['safety']}
Key Findings: {result['key_findings']}
Recommendation: {result['recommendation']}
{'='*50}
Analysis Length: {result['analysis_length']} tokens
"""
    return formatted_output

def main():
    setup_device()
    
    urls = [
        "https://trezor--model.webflow.io/"
    ]
    
    analysis_length = 1024  # 토큰 수로 설정
    results = classify_urls(urls, analysis_length=analysis_length)
    
    print("\nAnalysis Results:")
    print("="*50)
    for result in results:
        print(format_result(result))
        print("-"*50)
    
    print("\nGPU memory usage:")
    print_gpu_memory()

if __name__ == "__main__":
    main()