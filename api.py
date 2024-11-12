from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from typing import Dict, Optional
import logging
from urllib.parse import urlparse

from utils.config import Config
from main import URLSecurityAnalyzer

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# API 모델
class URLAnalysisRequest(BaseModel):
    url: HttpUrl
    timeout: Optional[int] = 30
    max_retries: Optional[int] = 3

class URLAnalysisResponse(BaseModel):
    status: str
    result: Optional[Dict] = None
    error: Optional[str] = None

# 싱글톤 분석기
analyzer = URLSecurityAnalyzer(Config())

app = FastAPI(
    title="URL Security Analyzer API",
    description="URL 보안 분석 API",
    version="1.0.0"
)

# CORS 설정
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/analyze")
async def analyze_url(request: URLAnalysisRequest) -> URLAnalysisResponse:
    """URL 분석 엔드포인트"""
    try:
        url = str(request.url)
        
        # URL 유효성 검사
        parsed_url = urlparse(url)
        if not all([parsed_url.scheme, parsed_url.netloc]):
            raise HTTPException(status_code=400, detail="Invalid URL format")
            
        # main.py의 분석 기능 사용
        result = analyzer.analyze(url)
        return URLAnalysisResponse(
            status="completed",
            result=result
        )
            
    except Exception as e:
        logger.error(f"Error analyzing URL: {str(e)}")
        return URLAnalysisResponse(
            status="error",
            error=str(e)
        )

@app.get("/health")
async def health_check():
    """헬스체크 엔드포인트"""
    try:
        import torch
        return {
            "status": "healthy",
            "gpu_available": torch.cuda.is_available(),
            "gpu_memory_allocated": f"{torch.cuda.memory_allocated()/1e9:.2f}GB" if torch.cuda.is_available() else "N/A"
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e)
        }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "api:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )