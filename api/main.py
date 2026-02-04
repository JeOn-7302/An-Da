"""
피싱 탐지 API
URL 분석 + 시각 유사도 기반 멀티모달 피싱 탐지

Updated: pHash/SSIM 기반 시각 유사도 분석으로 변경 (DINOv2 → pHash+SSIM)
"""

import re
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from src.database import get_database
from src.unified_analyzer import get_unified_analyzer, AnalysisLayer
from src.spoofing_detector import get_spoofing_detector

# Optional imports for screenshot/visual analysis
try:
    from src.screenshot_capture import get_screenshot_capture
    SCREENSHOT_AVAILABLE = True
except ImportError:
    SCREENSHOT_AVAILABLE = False

try:
    from src.visual_similarity import get_visual_analyzer, get_reference_manager
    VISUAL_SIMILARITY_AVAILABLE = True
except ImportError:
    VISUAL_SIMILARITY_AVAILABLE = False

try:
    from src.whois_lookup import get_domain_info
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False


router = APIRouter()

# 스크린샷 저장 디렉토리
SCREENSHOT_DIR = Path(__file__).parent.parent / "data" / "screenshots"
SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)


# 도메인 유틸리티
def extract_domain(url: str) -> str:
    """URL에서 도메인 추출"""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        # www. 제거
        if domain.startswith("www."):
            domain = domain[4:]
        return domain
    except Exception:
        return ""


# API 응답 모델
class AnalyzeRequest(BaseModel):
    url: str = Field(..., description="분석할 URL")


class AnalyzeResponse(BaseModel):
    url: str
    is_phishing: bool
    risk_score: float = Field(..., ge=0.0, le=1.0, description="위험 점수 (0.0~1.0)")
    detected_brand: Optional[str] = Field(None, description="탐지된 브랜드")
    reason: list[str] = Field(default_factory=list, description="판정 근거")
    details: dict = Field(default_factory=dict, description="상세 분석 결과")
    analysis_id: Optional[int] = Field(None, description="분석 결과 ID (DB 저장)")


# 메인 분석 엔드포인트
@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_url_endpoint(request: AnalyzeRequest):
    """
    URL 피싱 여부 종합 분석

    - 규칙 기반 스푸핑 탐지 (브랜드 사칭, 유사 문자 등)
    - URL 패턴 분석 (BERT 기반)
    - 시각 유사도 분석 (pHash + SSIM)
    """
    url = request.url
    details = {}

    # URL 형식 검증
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    domain = extract_domain(url)
    if not domain:
        raise HTTPException(status_code=400, detail="유효하지 않은 URL입니다.")

    details["domain"] = domain

    # 1. 통합 분석기 사용 (규칙 기반 + BERT ML)
    unified_analyzer = get_unified_analyzer()
    analysis_result = unified_analyzer.analyze(url)

    # 레이어별 결과 수집
    reasons = analysis_result.reasons.copy()
    suspicious_patterns = []
    url_phishing_prob = 0.0

    for layer_result in analysis_result.layer_results:
        details[layer_result.layer.value] = {
            "is_dangerous": layer_result.is_dangerous,
            "confidence": round(layer_result.confidence, 4),
            "reason": layer_result.reason,
            "details": layer_result.details
        }

        if layer_result.layer == AnalysisLayer.BERT_ML:
            url_phishing_prob = layer_result.confidence
            if layer_result.details.get("suspicious_patterns"):
                suspicious_patterns.extend(layer_result.details["suspicious_patterns"])

        elif layer_result.layer == AnalysisLayer.RULE_BASED:
            if layer_result.details.get("homograph"):
                suspicious_patterns.append("Homograph attack detected")
            if layer_result.details.get("typosquatting"):
                suspicious_patterns.append("Typosquatting detected")
            if layer_result.details.get("suspicious_tld"):
                suspicious_patterns.append("Suspicious TLD")

    is_phishing = analysis_result.is_phishing
    risk_score = analysis_result.final_confidence
    detected_brand = analysis_result.detected_brand

    # 2. 스크린샷 캡처 및 시각 유사도 분석 (Optional)
    visual_similarity = 0.0
    screenshot_path = None

    if SCREENSHOT_AVAILABLE and VISUAL_SIMILARITY_AVAILABLE and detected_brand:
        try:
            capture = get_screenshot_capture()
            screenshot_result = capture.capture(url)

            if screenshot_result:
                screenshot_path = str(screenshot_result)
                details["screenshot_path"] = screenshot_path

                # 레퍼런스 이미지가 있으면 유사도 비교
                ref_manager = get_reference_manager()
                ref_path = ref_manager.get_reference_path(detected_brand)

                if ref_path:
                    visual_analyzer = get_visual_analyzer()
                    similarity_result = visual_analyzer.analyze(screenshot_result, ref_path)
                    visual_similarity = similarity_result.combined_similarity

                    details["visual_analysis"] = {
                        "phash_similarity": round(similarity_result.phash_similarity, 4),
                        "ssim_similarity": round(similarity_result.ssim_similarity, 4),
                        "combined_similarity": round(visual_similarity, 4),
                        "is_similar": similarity_result.is_similar,
                        "method": "pHash(40%) + SSIM(60%)"
                    }

                    if similarity_result.is_similar and is_phishing:
                        reasons.append(f"시각 유사도 {visual_similarity:.1%} ('{detected_brand}' 사칭 의심)")
                else:
                    details["visual_analysis"] = {
                        "status": "no_reference",
                        "message": f"'{detected_brand}' 레퍼런스 이미지 없음"
                    }
        except Exception as e:
            details["screenshot_error"] = str(e)

    # 3. WHOIS 정보 조회 (Optional)
    whois_info = None
    if WHOIS_AVAILABLE:
        try:
            whois_result = await get_domain_info(domain)
            if whois_result.success:
                whois_info = {
                    "created_date": whois_result.created_date,
                    "registrar": whois_result.registrar,
                }
                details["whois"] = whois_info
        except Exception as e:
            details["whois_error"] = str(e)

    # 4. 데이터베이스 저장
    analysis_id = None
    try:
        db = get_database()

        # 익명 카운터 증가
        db.increment_analysis_count(is_safe=not is_phishing)

        # 피싱만 상세 저장
        if is_phishing:
            analysis_id = db.save_analysis(
                url=url,
                domain=domain,
                is_phishing=is_phishing,
                risk_score=round(risk_score, 4),
                detected_brand=detected_brand,
                screenshot_path=screenshot_path
            )

            ai_reasoning = " | ".join(reasons)
            db.save_phishing_detail(
                analysis_id=analysis_id,
                impersonated_brand=detected_brand or "unknown",
                ai_reasoning=ai_reasoning,
                url_phishing_prob=url_phishing_prob,
                visual_similarity=visual_similarity,
                suspicious_patterns=suspicious_patterns
            )

        details["analysis_id"] = analysis_id

    except Exception as e:
        details["db_error"] = str(e)

    return AnalyzeResponse(
        url=url,
        is_phishing=is_phishing,
        risk_score=round(risk_score, 4),
        detected_brand=detected_brand,
        reason=reasons,
        details=details,
        analysis_id=analysis_id
    )


@router.get("/health")
async def health_check():
    """API 상태 확인"""
    return {"status": "healthy", "service": "phishing-detection"}


# 대시보드용 API 엔드포인트
@router.get("/dashboard/statistics")
async def get_statistics():
    """통계 데이터 조회"""
    db = get_database()
    return db.get_statistics()


@router.get("/dashboard/phishing-cases")
async def get_phishing_cases(limit: int = 100):
    """피싱 케이스 목록 조회 (경찰용)"""
    db = get_database()
    return db.get_phishing_cases(limit=limit)


@router.get("/dashboard/recent")
async def get_recent_analyses(limit: int = 50):
    """최근 분석 결과 조회"""
    db = get_database()
    return db.get_recent_analyses(limit=limit)


@router.get("/analysis/{analysis_id}")
async def get_analysis_detail(analysis_id: int):
    """특정 분석 결과 상세 조회"""
    db = get_database()
    analysis = db.get_analysis_by_id(analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="분석 결과를 찾을 수 없습니다.")

    phishing_detail = db.get_phishing_detail(analysis_id)
    return {
        "analysis": analysis,
        "phishing_detail": phishing_detail
    }
