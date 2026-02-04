"""
통합 URL 분석 엔진
- Layer 1: 규칙 기반 스푸핑 탐지 (빠름)
- Layer 2: BERT ML 모델 분석 (정확)
- Layer 3: LLM 의도 분석 (향후 확장)
"""

from dataclasses import dataclass, field
from typing import Optional, List
from enum import Enum

from src.spoofing_detector import get_spoofing_detector, SpoofingResult
from src.url_analyzer import get_url_analyzer, URLAnalysisResult


class AnalysisLayer(Enum):
    """분석 레이어"""
    RULE_BASED = "rule_based"      # 규칙 기반 스푸핑 탐지
    BERT_ML = "bert_ml"            # BERT ML 모델
    LLM_INTENT = "llm_intent"      # LLM 의도 분석 (향후)


@dataclass
class LayerResult:
    """개별 레이어 분석 결과"""
    layer: AnalysisLayer
    is_dangerous: bool
    confidence: float
    reason: str
    details: dict = field(default_factory=dict)
    enabled: bool = True


@dataclass
class UnifiedAnalysisResult:
    """통합 분석 결과"""
    url: str

    # 최종 판정
    is_phishing: bool
    final_confidence: float
    risk_level: str  # safe, low, medium, high, critical
    detected_brand: Optional[str]

    # 레이어별 결과
    layer_results: List[LayerResult] = field(default_factory=list)

    # 탐지 이유 (사용자용)
    reasons: List[str] = field(default_factory=list)

    # AI 분석 상태 (UI 표시용)
    ai_status: dict = field(default_factory=dict)


class UnifiedAnalyzer:
    """
    통합 URL 분석기

    분석 순서:
    1. 규칙 기반 스푸핑 탐지 (빠른 필터링)
    2. BERT ML 모델 (정밀 분석)
    3. LLM 의도 분석 (향후 확장)
    """

    def __init__(self, enable_bert: bool = True, enable_llm: bool = False):
        self.enable_bert = enable_bert
        self.enable_llm = enable_llm

        # 레이어별 분석기
        self._spoofing_detector = None
        self._url_analyzer = None
        self._llm_analyzer = None  # 향후 구현

    @property
    def spoofing_detector(self):
        if self._spoofing_detector is None:
            self._spoofing_detector = get_spoofing_detector()
        return self._spoofing_detector

    @property
    def url_analyzer(self):
        if self._url_analyzer is None:
            self._url_analyzer = get_url_analyzer()
        return self._url_analyzer

    def analyze(self, url: str) -> UnifiedAnalysisResult:
        """
        URL 통합 분석

        Args:
            url: 분석할 URL

        Returns:
            UnifiedAnalysisResult: 통합 분석 결과
        """
        result = UnifiedAnalysisResult(
            url=url,
            is_phishing=False,
            final_confidence=0.0,
            risk_level="safe",
            detected_brand=None,
            ai_status={
                "rule_based": {"enabled": True, "status": "pending"},
                "bert_ml": {"enabled": self.enable_bert, "status": "pending" if self.enable_bert else "disabled"},
                "llm_intent": {"enabled": self.enable_llm, "status": "pending" if self.enable_llm else "disabled"},
            }
        )

        # Layer 1: 규칙 기반 스푸핑 탐지
        layer1_result = self._analyze_layer1_spoofing(url)
        result.layer_results.append(layer1_result)
        result.ai_status["rule_based"]["status"] = "completed"

        # 브랜드는 위험 여부와 관계없이 항상 설정 (공식 사이트도 브랜드 인식)
        if layer1_result.details.get("brand"):
            result.detected_brand = layer1_result.details.get("brand")

        # Layer 2: BERT ML 모델
        if self.enable_bert:
            layer2_result = self._analyze_layer2_bert(url)
            result.layer_results.append(layer2_result)
            result.ai_status["bert_ml"]["status"] = "completed"

        # Layer 3: LLM 의도 분석 (향후)
        if self.enable_llm:
            layer3_result = self._analyze_layer3_llm(url)
            result.layer_results.append(layer3_result)
            result.ai_status["llm_intent"]["status"] = "completed"

        # 최종 판정 계산
        self._calculate_final_verdict(result)

        return result

    def _analyze_layer1_spoofing(self, url: str) -> LayerResult:
        """Layer 1: 규칙 기반 스푸핑 탐지"""
        spoofing = self.spoofing_detector.analyze(url)

        details = {
            "brand": spoofing.target_brand,
            "homograph": bool(spoofing.homograph_attacks),
            "typosquatting": bool(spoofing.typosquatting),
            "suspicious_tld": spoofing.suspicious_tld,
            "subdomain_abuse": spoofing.subdomain_abuse,
            "brand_abuse": bool(spoofing.brand_abuse),
        }

        reason = ""
        if spoofing.is_spoofing:
            reasons = []
            if spoofing.brand_abuse:
                reasons.append(f"'{spoofing.target_brand}' 브랜드 사칭")
            if spoofing.homograph_attacks:
                reasons.append("유사 문자 공격")
            if spoofing.suspicious_tld:
                reasons.append("의심 TLD")
            reason = ", ".join(reasons) if reasons else "스푸핑 의심"

        return LayerResult(
            layer=AnalysisLayer.RULE_BASED,
            is_dangerous=spoofing.is_spoofing,
            confidence=spoofing.confidence,
            reason=reason,
            details=details,
            enabled=True
        )

    def _analyze_layer2_bert(self, url: str) -> LayerResult:
        """Layer 2: BERT ML 모델 분석"""
        try:
            bert_result = self.url_analyzer.analyze(url)

            details = {
                "phishing_probability": bert_result.phishing_probability,
                "risk_level": bert_result.risk_level,
                "suspicious_patterns": bert_result.suspicious_patterns,
                "features": bert_result.features,
            }

            reason = ""
            if bert_result.is_suspicious:
                if bert_result.suspicious_patterns:
                    reason = f"ML 탐지: {', '.join(bert_result.suspicious_patterns[:2])}"
                else:
                    reason = f"ML 피싱 확률 {bert_result.phishing_probability:.0%}"

            return LayerResult(
                layer=AnalysisLayer.BERT_ML,
                is_dangerous=bert_result.is_suspicious,
                confidence=bert_result.phishing_probability,
                reason=reason,
                details=details,
                enabled=True
            )
        except Exception as e:
            return LayerResult(
                layer=AnalysisLayer.BERT_ML,
                is_dangerous=False,
                confidence=0.0,
                reason=f"분석 실패: {str(e)}",
                details={"error": str(e)},
                enabled=True
            )

    def _analyze_layer3_llm(self, url: str) -> LayerResult:
        """Layer 3: LLM 의도 분석 (향후 구현)"""
        # TODO: OpenAI/Claude API 연동
        return LayerResult(
            layer=AnalysisLayer.LLM_INTENT,
            is_dangerous=False,
            confidence=0.0,
            reason="LLM 분석 미구현 (향후 지원 예정)",
            details={"status": "not_implemented"},
            enabled=False
        )

    def _calculate_final_verdict(self, result: UnifiedAnalysisResult):
        """최종 판정 계산"""
        # 레이어별 가중치
        weights = {
            AnalysisLayer.RULE_BASED: 0.4,
            AnalysisLayer.BERT_ML: 0.5,
            AnalysisLayer.LLM_INTENT: 0.1,  # 향후 활성화 시
        }

        total_weight = 0.0
        weighted_confidence = 0.0
        any_dangerous = False

        for layer_result in result.layer_results:
            if not layer_result.enabled:
                continue

            weight = weights.get(layer_result.layer, 0.1)
            total_weight += weight
            weighted_confidence += layer_result.confidence * weight

            if layer_result.is_dangerous:
                any_dangerous = True
                result.reasons.append(f"[{layer_result.layer.value}] {layer_result.reason}")

        # 최종 신뢰도 계산
        if total_weight > 0:
            result.final_confidence = weighted_confidence / total_weight
        else:
            result.final_confidence = 0.0

        # 최종 판정
        # 규칙: 어느 하나라도 위험 판정이면 + 신뢰도 30% 이상이면 피싱
        result.is_phishing = any_dangerous and result.final_confidence >= 0.3

        # 위험 수준 결정
        if result.final_confidence >= 0.8:
            result.risk_level = "critical"
        elif result.final_confidence >= 0.6:
            result.risk_level = "high"
        elif result.final_confidence >= 0.4:
            result.risk_level = "medium"
        elif result.final_confidence >= 0.2:
            result.risk_level = "low"
        else:
            result.risk_level = "safe"

        # 사용자 친화적 이유 생성
        if not result.reasons:
            if result.is_phishing:
                result.reasons.append("의심스러운 URL 패턴이 탐지되었습니다")
            else:
                result.reasons.append("안전한 것으로 판단됩니다")


# 싱글톤 인스턴스
_unified_analyzer: Optional[UnifiedAnalyzer] = None


def get_unified_analyzer(enable_bert: bool = True, enable_llm: bool = False) -> UnifiedAnalyzer:
    """통합 분석기 싱글톤 인스턴스"""
    global _unified_analyzer
    if _unified_analyzer is None:
        _unified_analyzer = UnifiedAnalyzer(enable_bert=enable_bert, enable_llm=enable_llm)
    return _unified_analyzer
