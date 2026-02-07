# 1단계: 베이스 이미지 설정 (가볍고 보안에 강한 slim 버전 사용)
FROM python:3.11-slim

# 2단계: 환경 변수 설정 (Python 출력 최적화 및 .pyc 생성 방지)
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# 3단계: 작업 디렉토리 생성
WORKDIR /app

# 4단계: 시스템 의존성 설치 (필요한 경우만 설치하여 이미지 크기 최소화)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# 5단계: 종속성 설치 (레이어 캐싱 활용을 위해 requirements부터 복사)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 6단계: 소스 코드 복사
COPY . .

# 7단계: 포트 설정 (FastAPI 기본 포트)
EXPOSE 8000

# 8단계: 실행 명령 (Uvicorn을 사용한 비동기 서버 실행)
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]