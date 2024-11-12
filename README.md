# URL Security Analyzer

URL Security Analyzer는 LLaMA 모델을 활용한 URL 보안 분석 도구입니다. 악성 URL, 피싱 사이트 등을 탐지하고 상세한 보안 분석 보고서를 제공합니다.

## 주요 기능

- URL 악성코드 및 피싱 탐지
- 도메인 평판 분석
- SSL/TLS 인증서 검증
- 보안 헤더 분석
- 콘텐츠 기반 위협 탐지
- Edge 브라우저 확장 프로그램 제공

## 시스템 요구사항

- Python 3.10.0
- CUDA 지원 GPU (권장)
- 최소 16GB RAM
- Microsoft Edge 브라우저 (확장 프로그램용)
- pipenv (의존성 관리)

## 설치 방법

1. 저장소 클론
```bash
git clone https://github.com/Vampirk/URL_Classfifer_LLM.git
cd URL_Classfifer_LLM
```

2. Pipenv 설치 (없는 경우)
```bash
pip install pipenv
```

3. 가상환경 생성 및 의존성 설치
```bash
pipenv install
```

4. 가상환경 활성화
```bash
pipenv shell
```

### 주요 의존성
```
accelerate==1.1.0
bitsandbytes==0.44.1
bs4==0.0.2
datasets==3.1.0
dnspython==2.7.0
fastapi==0.115.4
matplotlib==3.9.2
pyOpenSSL==24.2.1
python-whois==0.9.4
scikit-learn==1.5.2
tabulate==0.9.0
termcolor==2.5.0
transformers==4.46.1
uvicorn==0.32.0
```

4. LLaMA 모델 설정
- `Meta-Llama-3.1-8B-Instruct` 모델 파일을 프로젝트 디렉토리에 배치

## 사용 방법

### CLI 도구 실행
```bash
# 가상환경 내에서
python main.py --url https://example.com
```

### API 서버 실행
```bash
# 가상환경 내에서
python api.py
```
- API 서버는 기본적으로 `http://localhost:8000`에서 실행됩니다.

### Edge 확장 프로그램 설치
1. Edge 브라우저에서 `edge://extensions` 접속
2. 개발자 모드 활성화
3. "압축해제된 확장 프로그램 로드" 선택
4. `url-analyzer-extension` 디렉토리 선택

## API 엔드포인트

- `POST /analyze`: URL 분석 요청
  ```json
  {
    "url": "https://example.com",
    "timeout": 30,
    "max_retries": 3
  }
  ```
- `GET /health`: 서버 상태 확인

## 프로젝트 구조
```
URLSecurityAnalyzer/
├── analyzers/           # 분석 모듈
├── models/             # ML 모델
├── utils/              # 유틸리티 함수
├── url-analyzer-extension/  # Edge 확장 프로그램
├── main.py            # CLI 도구
├── api.py             # FastAPI 서버
├── Pipfile            # Pipenv 의존성 정의
└── Pipfile.lock       # Pipenv 의존성 잠금 파일
```

## 개발 환경

이 프로젝트는 pipenv를 사용하여 의존성을 관리합니다. 모든 의존성은 Pipfile과 Pipfile.lock에 정의되어 있으며, 다음 명령으로 개발 환경을 설정할 수 있습니다:

```bash
# 개발 환경 설정
pipenv install --dev

# 의존성 추가
pipenv install package_name

# 현재 의존성 트리 확인
pipenv graph
```

## 라이선스

이 프로젝트는 MIT 라이선스 하에 있습니다.

## 기여하기

1. Fork the Project (https://github.com/Vampirk/URL_Classfifer_LLM)
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 문의사항

문제가 발생하거나 제안사항이 있으시다면 [GitHub Issues](https://github.com/Vampirk/URL_Classfifer_LLM/issues)를 통해 알려주세요.

## 주의사항

- 이 도구는 보안 분석을 위한 참고용으로만 사용해야 합니다.
- 실제 보안 결정은 추가적인 전문가 검토가 필요합니다.
- GPU 메모리 사용량이 높을 수 있으므로 시스템 리소스를 모니터링하세요.
- LLaMA 모델의 라이선스 및 사용 조건을 반드시 확인하고 준수하세요.
