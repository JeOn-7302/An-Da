"""
Memcyco-style Spoofing Detector
시각적 스푸핑 탐지: 유사 문자, 일반 TLD, 브랜드 사칭 패턴 분석

브랜드 정보는 DB에서 동적으로 로드됩니다.
"""

import re
from dataclasses import dataclass, field
from typing import Optional, Dict, List
from urllib.parse import urlparse

try:
    import tldextract
except ImportError:
    tldextract = None

# DB 연동 (순환 import 방지를 위해 함수 내에서 import)
def _get_brands_from_db() -> Dict[str, dict]:
    """DB에서 브랜드 정보 로드"""
    try:
        from src.database import get_database
        db = get_database()

        # 기본 브랜드가 없으면 초기화
        brands_list = db.get_all_brands()
        if not brands_list:
            db.init_default_brands()
            brands_list = db.get_all_brands()

        # spoofing_detector 형식으로 변환
        brands = {}
        for b in brands_list:
            brands[b['name']] = {
                'official_domains': b['official_domains'],
                'keywords': b['keywords'] + b.get('typos', []),
                'display_name': b['display_name']
            }
        return brands
    except Exception as e:
        print(f"[SpoofingDetector] DB 브랜드 로드 실패, 기본값 사용: {e}")
        return FALLBACK_BRAND_PATTERNS


@dataclass
class SpoofingResult:
    """스푸핑 탐지 결과"""
    is_spoofing: bool = False
    confidence: float = 0.0
    spoofing_type: str = ""
    target_brand: Optional[str] = None

    # 상세 분석
    homograph_attacks: list = field(default_factory=list)  # 유사 문자 공격
    typosquatting: list = field(default_factory=list)  # 오타 도메인
    brand_abuse: list = field(default_factory=list)  # 브랜드 남용
    suspicious_tld: bool = False  # 의심스러운 TLD
    subdomain_abuse: bool = False  # 서브도메인 남용

    # 심리 분석용
    intent_indicators: list = field(default_factory=list)  # 의도 지표
    urgency_signals: list = field(default_factory=list)  # 긴급성 신호
    trust_manipulation: list = field(default_factory=list)  # 신뢰 조작


# 유사 문자 매핑 (Homograph Attack)
LOOKALIKE_CHARS = {
    'a': ['а', 'ɑ', 'α', '@', '4'],  # 키릴 문자, 그리스 문자
    'b': ['Ь', 'ь', '6', 'ß'],
    'c': ['с', 'ϲ', '(', '<'],
    'd': ['ԁ', 'ɗ'],
    'e': ['е', 'ё', 'э', '3'],
    'g': ['ɡ', '9'],
    'h': ['һ', 'н'],
    'i': ['і', 'ı', '1', 'l', '|'],
    'j': ['ј'],
    'k': ['κ', 'к'],
    'l': ['1', 'I', '|', 'ӏ'],
    'm': ['м', 'rn'],
    'n': ['п', 'ո'],
    'o': ['о', 'ο', '0', 'ө'],
    'p': ['р', 'ρ'],
    'q': ['գ'],
    'r': ['г', 'ɾ'],
    's': ['ѕ', '$', '5'],
    't': ['т', '+'],
    'u': ['υ', 'ս', 'µ'],
    'v': ['ν', 'ѵ'],
    'w': ['ω', 'ѡ', 'vv'],
    'x': ['х', '×'],
    'y': ['у', 'ү', 'γ'],
    'z': ['ᴢ'],
}

# 브랜드 목록 (DB 로드 실패 시 폴백용)
FALLBACK_BRAND_PATTERNS = {
    'naver': {
        'official_domains': ['naver.com', 'navercorp.com'],
        'keywords': ['naver', 'naverr', 'naveer', 'n4ver', 'nаver'],
        'display_name': '네이버'
    },
    'kakao': {
        'official_domains': ['kakao.com', 'kakaobank.com', 'kakaopay.com', 'kakaocorp.com'],
        'keywords': ['kakao', 'kakaо', 'kаkao', 'kakaotalk', 'kakaopay'],
        'display_name': '카카오'
    },
    'google': {
        'official_domains': ['google.com', 'google.co.kr', 'googleapis.com'],
        'keywords': ['google', 'googie', 'g00gle', 'googlе'],
        'display_name': '구글'
    },
    'government': {
        'official_domains': ['go.kr', 'gov.kr', 'korea.kr'],
        'keywords': ['gov', 'government', '정부', 'korea', 'tax', 'refund'],
        'display_name': '정부기관'
    },
    'kbbank': {
        'official_domains': ['kbstar.com', 'kbcard.com'],
        'keywords': ['kbstar', 'kbbank', 'kb국민'],
        'display_name': 'KB국민은행'
    },
    'shinhan': {
        'official_domains': ['shinhan.com', 'shinhancard.com', 'shinhanbank.com'],
        'keywords': ['shinhan', 'shinhanbank', '신한'],
        'display_name': '신한은행'
    },
    'samsung': {
        'official_domains': ['samsung.com', 'samsungcard.com'],
        'keywords': ['samsung', 'samsumg', 'sаmsung'],
        'display_name': '삼성'
    },
}

# 의심스러운 TLD (일반적인 피싱에 사용)
SUSPICIOUS_TLDS = {
    'top', 'xyz', 'club', 'online', 'site', 'website', 'space',
    'tech', 'store', 'shop', 'click', 'link', 'info', 'pw', 'cc',
    'tk', 'ml', 'ga', 'cf', 'gq', 'work', 'date', 'racing', 'win',
    'bid', 'stream', 'download', 'accountant', 'loan', 'cricket'
}

# 긴급성 신호 키워드
URGENCY_KEYWORDS = {
    'ko': ['긴급', '즉시', '지금', '마감', '만료', '정지', '차단', '보안', '인증', '확인필요'],
    'en': ['urgent', 'immediately', 'now', 'expire', 'suspend', 'verify', 'confirm',
           'security', 'alert', 'warning', 'limited', 'act now', 'deadline']
}

# 신뢰 조작 키워드
TRUST_KEYWORDS = {
    'ko': ['공식', '인증', '안전', '보안', '정부', '은행', '카드', '본인확인'],
    'en': ['official', 'secure', 'verified', 'authorized', 'bank', 'government']
}


class SpoofingDetector:
    """Memcyco 스타일 스푸핑 탐지기"""

    def __init__(self):
        # DB에서 브랜드 로드 (동적 관리)
        self.brands = _get_brands_from_db()
        self.lookalikes = LOOKALIKE_CHARS

    def reload_brands(self):
        """브랜드 정보 다시 로드 (관리 UI에서 변경 시 호출)"""
        self.brands = _get_brands_from_db()

    def analyze(self, url: str, page_content: str = "") -> SpoofingResult:
        """URL 및 페이지 콘텐츠 스푸핑 분석"""
        result = SpoofingResult()

        # URL 파싱
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()

        # tldextract 사용 가능하면 상세 분석
        if tldextract:
            extracted = tldextract.extract(url)
            subdomain = extracted.subdomain
            domain_name = extracted.domain
            tld = extracted.suffix
        else:
            # 간단한 파싱 대체
            parts = domain.split('.')
            tld = parts[-1] if len(parts) > 1 else ''
            domain_name = parts[-2] if len(parts) > 1 else parts[0]
            subdomain = '.'.join(parts[:-2]) if len(parts) > 2 else ''

        # 공식 도메인 확인 (모든 브랜드에 대해)
        for brand_key, brand_info in self.brands.items():
            if self._is_official_domain(domain, brand_key):
                # 공식 도메인이면 안전 판정 후 바로 리턴
                result.target_brand = brand_key
                return result

        # 1. 브랜드 사칭 분석
        detected_brand, brand_abuse = self._detect_brand_abuse(domain, domain_name, subdomain, path)
        if detected_brand:
            result.target_brand = detected_brand
            result.brand_abuse = brand_abuse

            # 공식 도메인 확인
            is_official = self._is_official_domain(domain, detected_brand)
            if not is_official:
                result.is_spoofing = True
                result.spoofing_type = "brand_impersonation"
                result.confidence += 0.4

        # 2. 유사 문자 공격 (Homograph) 탐지
        homograph_attacks = self._detect_homograph_attack(domain_name)
        if homograph_attacks:
            result.homograph_attacks = homograph_attacks
            result.is_spoofing = True
            result.spoofing_type = "homograph_attack"
            result.confidence += 0.3

        # 3. 타이포스쿼팅 탐지
        typosquatting = self._detect_typosquatting(domain_name)
        if typosquatting:
            result.typosquatting = typosquatting
            result.is_spoofing = True
            result.confidence += 0.2

        # 4. 의심스러운 TLD 확인
        if tld in SUSPICIOUS_TLDS:
            result.suspicious_tld = True
            result.confidence += 0.15

        # 5. 서브도메인 남용 확인
        if subdomain and self._is_subdomain_abuse(subdomain):
            result.subdomain_abuse = True
            result.confidence += 0.15

        # 6. 페이지 콘텐츠 분석 (제공된 경우)
        if page_content:
            self._analyze_content(page_content, result)

        # 7. 심리 분석 지표 생성
        self._generate_psychological_indicators(result, url, domain)

        # 신뢰도 정규화 (최대 1.0)
        result.confidence = min(result.confidence, 1.0)

        return result

    def _detect_brand_abuse(self, full_domain: str, domain_name: str, subdomain: str, path: str) -> tuple:
        """브랜드 키워드 남용 탐지"""
        detected_brand = None
        abuse_details = []

        search_text = f"{subdomain}.{domain_name}{path}".lower()

        for brand_key, brand_info in self.brands.items():
            # 공식 도메인이면 브랜드만 인식하고 abuse는 기록하지 않음
            if any(official in full_domain for official in brand_info['official_domains']):
                detected_brand = brand_key
                continue

            # 키워드 매칭
            for keyword in brand_info['keywords']:
                if keyword.lower() in search_text:
                    detected_brand = brand_key
                    abuse_details.append({
                        'type': 'keyword_match',
                        'keyword': keyword,
                        'brand': brand_info['display_name'],
                        'location': 'domain' if keyword in domain_name else
                                   'subdomain' if keyword in subdomain else 'path'
                    })

        return detected_brand, abuse_details

    def _is_official_domain(self, domain: str, brand_key: str) -> bool:
        """공식 도메인 확인"""
        if brand_key not in self.brands:
            return False

        official_domains = self.brands[brand_key]['official_domains']
        return any(domain.endswith(official) for official in official_domains)

    def _detect_homograph_attack(self, domain_name: str) -> list:
        """유사 문자 공격 탐지"""
        attacks = []

        for char in domain_name:
            for latin_char, lookalikes in self.lookalikes.items():
                if char in lookalikes:
                    attacks.append({
                        'original_char': char,
                        'looks_like': latin_char,
                        'type': 'homograph',
                        'description': f"'{char}'는 '{latin_char}'처럼 보이는 다른 문자입니다"
                    })

        return attacks

    def _detect_typosquatting(self, domain_name: str) -> list:
        """타이포스쿼팅 탐지 (오타 도메인)"""
        typos = []

        typo_patterns = [
            (r'(.)\1{2,}', '문자 반복'),  # naverr, gooogle
            (r'[0-9]', '숫자 혼용'),  # nav3r, g00gle
            (r'-{2,}', '하이픈 반복'),
            (r'^-|-$', '하이픈 시작/끝'),
        ]

        for pattern, description in typo_patterns:
            if re.search(pattern, domain_name):
                typos.append({
                    'pattern': pattern,
                    'description': description,
                    'value': domain_name
                })

        return typos

    def _is_subdomain_abuse(self, subdomain: str) -> bool:
        """서브도메인 남용 확인"""
        # 너무 긴 서브도메인
        if len(subdomain) > 30:
            return True

        # 브랜드 키워드가 서브도메인에 있음
        for brand_info in self.brands.values():
            for keyword in brand_info['keywords']:
                if keyword in subdomain.lower():
                    return True

        # 공식처럼 보이는 서브도메인
        suspicious_subdomains = ['login', 'secure', 'account', 'verify', 'auth', 'signin', 'official']
        return any(sus in subdomain.lower() for sus in suspicious_subdomains)

    def _analyze_content(self, content: str, result: SpoofingResult):
        """페이지 콘텐츠 분석"""
        content_lower = content.lower()

        # 긴급성 신호 탐지
        for lang, keywords in URGENCY_KEYWORDS.items():
            for keyword in keywords:
                if keyword in content_lower:
                    result.urgency_signals.append({
                        'keyword': keyword,
                        'language': lang,
                        'type': 'urgency'
                    })

        # 신뢰 조작 탐지
        for lang, keywords in TRUST_KEYWORDS.items():
            for keyword in keywords:
                if keyword in content_lower:
                    result.trust_manipulation.append({
                        'keyword': keyword,
                        'language': lang,
                        'type': 'trust_manipulation'
                    })

    def _generate_psychological_indicators(self, result: SpoofingResult, url: str, domain: str):
        """심리 분석 지표 생성 (4-Quadrant Report용)"""

        # Intent (의도) 분석
        if result.brand_abuse:
            result.intent_indicators.append({
                'category': 'intent',
                'finding': f"'{result.target_brand}' 브랜드를 사칭하여 신뢰 탈취 시도",
                'severity': 'high'
            })

        if result.homograph_attacks:
            result.intent_indicators.append({
                'category': 'intent',
                'finding': "유사 문자를 사용한 시각적 속임수 시도",
                'severity': 'critical'
            })

        if result.suspicious_tld:
            result.intent_indicators.append({
                'category': 'intent',
                'finding': "피싱에 자주 사용되는 TLD 사용",
                'severity': 'medium'
            })


# 싱글톤 인스턴스
_detector_instance: Optional[SpoofingDetector] = None


def get_spoofing_detector() -> SpoofingDetector:
    """스푸핑 탐지기 싱글톤 인스턴스 반환"""
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = SpoofingDetector()
    return _detector_instance
