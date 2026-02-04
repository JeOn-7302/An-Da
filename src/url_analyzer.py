"""
URL 분석 모듈
Hugging Face 사전 학습 모델 기반 URL 피싱 탐지
"""

import re
from dataclasses import dataclass
from typing import Optional, List, Tuple
from urllib.parse import urlparse

import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification


@dataclass
class URLAnalysisResult:
    """URL 분석 결과"""
    url: str
    domain: str
    phishing_probability: float
    is_suspicious: bool
    risk_level: str  # "safe", "low", "medium", "high", "critical"
    suspicious_patterns: List[str]
    features: dict


class URLAnalyzer:
    """URL 패턴 기반 피싱 탐지"""

    MODEL_NAME = "ealvaradob/bert-finetuned-phishing"

    # 위험 키워드
    BRAND_KEYWORDS = [
        "naver", "kakao", "google", "samsung", "apple", "microsoft",
        "bank", "shinhan", "kookmin", "woori", "hana", "ibk", "nh",
        "gov", "police", "tax", "pension", "insurance"
    ]

    def __init__(self):
        self.tokenizer = None
        self.model = None
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self._loaded = False

    def load(self):
        """모델 지연 로딩"""
        if self._loaded:
            return
        print("[URLAnalyzer] 모델 로딩 중...")
        self.tokenizer = AutoTokenizer.from_pretrained(self.MODEL_NAME)
        self.model = AutoModelForSequenceClassification.from_pretrained(self.MODEL_NAME)
        self.model.to(self.device)
        self.model.eval()
        self._loaded = True
        print(f"[URLAnalyzer] 모델 로딩 완료 (device: {self.device})")

    def extract_domain(self, url: str) -> str:
        """URL에서 도메인 추출"""
        try:
            if not url.startswith(("http://", "https://")):
                url = "https://" + url
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            if domain.startswith("www."):
                domain = domain[4:]
            return domain
        except Exception:
            return ""

    def extract_features(self, url: str) -> dict:
        """URL에서 특징 추출"""
        domain = self.extract_domain(url)

        features = {
            "url_length": len(url),
            "domain_length": len(domain),
            "subdomain_count": domain.count("."),
            "has_ip_address": bool(re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url)),
            "has_at_symbol": "@" in url,
            "has_double_slash": "//" in url[8:],  # 프로토콜 이후
            "dash_count": url.count("-"),
            "underscore_count": url.count("_"),
            "digit_count": sum(c.isdigit() for c in domain),
            "special_char_count": sum(not c.isalnum() and c != "." for c in domain),
            "path_length": len(urlparse(url).path),
            "query_length": len(urlparse(url).query),
            "is_https": url.startswith("https://"),
            "suspicious_tld": any(domain.endswith(tld) for tld in [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top"]),
        }

        # 브랜드 키워드 포함 여부
        features["contains_brand_keyword"] = any(kw in domain for kw in self.BRAND_KEYWORDS)
        features["brand_keywords_found"] = [kw for kw in self.BRAND_KEYWORDS if kw in domain]

        return features

    def detect_suspicious_patterns(self, url: str) -> List[str]:
        """의심스러운 패턴 탐지"""
        patterns = []
        domain = self.extract_domain(url)
        features = self.extract_features(url)

        # IP 주소 사용
        if features["has_ip_address"]:
            patterns.append("IP 주소 직접 사용")

        # 과도한 서브도메인
        if features["subdomain_count"] >= 3:
            patterns.append("과도한 서브도메인 사용")

        # 브랜드명 포함 의심 도메인
        if features["brand_keywords_found"]:
            patterns.append(f"브랜드 키워드 포함: {', '.join(features['brand_keywords_found'])}")

        # 특수문자 과다
        if features["dash_count"] >= 3:
            patterns.append("하이픈(-) 과다 사용")
        if features["underscore_count"] >= 2:
            patterns.append("언더스코어(_) 과다 사용")

        # 긴 URL
        if features["url_length"] > 100:
            patterns.append("비정상적으로 긴 URL")

        # 의심스러운 TLD
        if features["suspicious_tld"]:
            patterns.append("의심스러운 최상위 도메인")

        # @ 기호 (피싱에서 자주 사용)
        if features["has_at_symbol"]:
            patterns.append("@ 기호 포함 (URL 스푸핑 의심)")

        # HTTPS 미사용
        if not features["is_https"]:
            patterns.append("HTTPS 미사용")

        # 숫자 과다
        if features["digit_count"] >= 5:
            patterns.append("도메인에 숫자 과다 사용")

        return patterns

    def predict_phishing_probability(self, url: str) -> Tuple[float, bool]:
        """
        ML 모델로 피싱 확률 예측

        Returns:
            Tuple[float, bool]: (피싱 확률 0.0~1.0, is_suspicious)
        """
        self.load()

        with torch.no_grad():
            inputs = self.tokenizer(
                url,
                return_tensors="pt",
                truncation=True,
                max_length=512,
                padding=True
            ).to(self.device)

            outputs = self.model(**inputs)
            probs = torch.softmax(outputs.logits, dim=1)
            phishing_prob = probs[0][1].item()

        return phishing_prob, phishing_prob > 0.5

    def determine_risk_level(self, phishing_prob: float, pattern_count: int) -> str:
        """위험 수준 결정"""
        # 복합 점수 계산
        combined_score = phishing_prob * 0.7 + min(pattern_count * 0.1, 0.3)

        if combined_score >= 0.8:
            return "critical"
        elif combined_score >= 0.6:
            return "high"
        elif combined_score >= 0.4:
            return "medium"
        elif combined_score >= 0.2:
            return "low"
        else:
            return "safe"

    def analyze(self, url: str) -> URLAnalysisResult:
        """
        URL 종합 분석

        Args:
            url: 분석할 URL

        Returns:
            URLAnalysisResult: 분석 결과
        """
        # URL 정규화
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        domain = self.extract_domain(url)
        features = self.extract_features(url)
        suspicious_patterns = self.detect_suspicious_patterns(url)
        phishing_prob, is_suspicious = self.predict_phishing_probability(url)
        risk_level = self.determine_risk_level(phishing_prob, len(suspicious_patterns))

        return URLAnalysisResult(
            url=url,
            domain=domain,
            phishing_probability=phishing_prob,
            is_suspicious=is_suspicious,
            risk_level=risk_level,
            suspicious_patterns=suspicious_patterns,
            features=features
        )


# 싱글톤 인스턴스
_analyzer_instance: Optional[URLAnalyzer] = None


def get_url_analyzer() -> URLAnalyzer:
    """URLAnalyzer 싱글톤 인스턴스 반환"""
    global _analyzer_instance
    if _analyzer_instance is None:
        _analyzer_instance = URLAnalyzer()
    return _analyzer_instance


# 테스트용
if __name__ == "__main__":
    analyzer = URLAnalyzer()

    test_urls = [
        "https://www.naver.com",
        "https://naver-login.suspicious-site.com/auth",
        "http://192.168.1.1/login",
        "https://www.g00gle.com/signin",
    ]

    for url in test_urls:
        result = analyzer.analyze(url)
        print(f"\n{'='*60}")
        print(f"URL: {result.url}")
        print(f"Domain: {result.domain}")
        print(f"Phishing Probability: {result.phishing_probability:.1%}")
        print(f"Risk Level: {result.risk_level}")
        print(f"Suspicious Patterns: {result.suspicious_patterns}")
