"""
Law Enforcement Integration Module
경찰청 연동 모듈 - 표준화된 신고 스키마, 익명화, PDF 리포트 생성
"""

import json
import hashlib
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse
import base64


@dataclass
class TechnicalMetadata:
    """기술적 메타데이터"""
    domain: str = ""
    ip_address: Optional[str] = None
    registrar: Optional[str] = None
    domain_created: Optional[str] = None
    ssl_issuer: Optional[str] = None
    ssl_valid_from: Optional[str] = None
    redirect_chain: list = field(default_factory=list)
    hosting_country: Optional[str] = None


@dataclass
class ThreatIndicators:
    """위협 지표"""
    visual_similarity: float = 0.0
    url_phishing_score: float = 0.0
    homograph_detected: bool = False
    typosquatting_detected: bool = False
    suspicious_tld: bool = False
    brand_impersonation: bool = False
    urgency_keywords_count: int = 0
    trust_manipulation_count: int = 0


@dataclass
class LawEnforcementReport:
    """경찰청 신고용 표준화 리포트"""
    # 기본 정보
    report_id: str = ""
    report_timestamp: str = ""

    # 위협 분류
    threat_level: str = "Low"  # Low / Medium / High / Critical
    tactic_category: list = field(default_factory=list)  # Authority / Urgency / Reward / Fear

    # URL 정보
    suspicious_url: str = ""
    target_brand: Optional[str] = None

    # 기술적 메타데이터
    technical_metadata: TechnicalMetadata = field(default_factory=TechnicalMetadata)

    # 위협 지표
    threat_indicators: ThreatIndicators = field(default_factory=ThreatIndicators)

    # AI 분석 요약
    llm_summary: str = ""
    detailed_findings: list = field(default_factory=list)

    # 4-Quadrant 분석
    quadrant_intent: list = field(default_factory=list)
    quadrant_action: list = field(default_factory=list)
    quadrant_psychology: list = field(default_factory=list)
    quadrant_result: list = field(default_factory=list)

    # 익명화된 신고자 정보 (선택적)
    anonymous_reporter_hash: Optional[str] = None


class AnonymizationModule:
    """프라이버시 우선 익명화 모듈"""

    @staticmethod
    def generate_anonymous_id(user_identifier: str = "") -> str:
        """사용자 식별자를 익명화된 해시로 변환"""
        if not user_identifier:
            # 타임스탬프 기반 임의 ID 생성
            user_identifier = f"anon_{datetime.now().timestamp()}"

        # SHA-256 해시 + 솔트
        salt = "anda_anonymous_2024"
        hashed = hashlib.sha256(f"{salt}{user_identifier}".encode()).hexdigest()
        return hashed[:16]  # 앞 16자리만 사용

    @staticmethod
    def remove_pii(text: str) -> str:
        """텍스트에서 개인식별정보(PII) 제거"""
        # 이메일 주소 마스킹
        text = re.sub(
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            '[EMAIL_REDACTED]',
            text
        )

        # 전화번호 마스킹 (한국 형식)
        text = re.sub(
            r'(010|011|016|017|018|019)[-.\s]?\d{3,4}[-.\s]?\d{4}',
            '[PHONE_REDACTED]',
            text
        )

        # 주민등록번호 마스킹
        text = re.sub(
            r'\d{6}[-.\s]?\d{7}',
            '[RRN_REDACTED]',
            text
        )

        # IP 주소는 유지 (위협 분석에 필요)

        return text

    @staticmethod
    def sanitize_url_for_sharing(url: str) -> str:
        """URL에서 민감한 쿼리 파라미터 제거"""
        parsed = urlparse(url)

        # 민감한 파라미터 목록
        sensitive_params = [
            'token', 'auth', 'key', 'password', 'pwd', 'secret',
            'session', 'sid', 'user', 'username', 'email'
        ]

        # 쿼리 파라미터 필터링
        if parsed.query:
            params = parsed.query.split('&')
            filtered_params = []
            for param in params:
                key = param.split('=')[0].lower()
                if not any(s in key for s in sensitive_params):
                    filtered_params.append(param)
                else:
                    filtered_params.append(f"{param.split('=')[0]}=[REDACTED]")

            # URL 재구성
            sanitized_query = '&'.join(filtered_params)
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{sanitized_query}" if sanitized_query else f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        return url


class ReportGenerator:
    """리포트 생성기"""

    def __init__(self):
        self.anonymizer = AnonymizationModule()

    def generate_report_id(self) -> str:
        """고유 리포트 ID 생성"""
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        random_part = hashlib.md5(str(datetime.now().timestamp()).encode()).hexdigest()[:6]
        return f"SG-{timestamp}-{random_part.upper()}"

    def determine_threat_level(self, indicators: ThreatIndicators) -> str:
        """위협 수준 결정"""
        score = 0

        # 시각적 유사도
        if indicators.visual_similarity >= 0.9:
            score += 40
        elif indicators.visual_similarity >= 0.7:
            score += 25

        # URL 피싱 점수
        if indicators.url_phishing_score >= 0.8:
            score += 30
        elif indicators.url_phishing_score >= 0.5:
            score += 15

        # 기타 지표
        if indicators.homograph_detected:
            score += 15
        if indicators.typosquatting_detected:
            score += 10
        if indicators.suspicious_tld:
            score += 10
        if indicators.brand_impersonation:
            score += 20

        # 심리 조작 지표
        score += min(indicators.urgency_keywords_count * 5, 15)
        score += min(indicators.trust_manipulation_count * 5, 15)

        # 위협 수준 결정
        if score >= 70:
            return "Critical"
        elif score >= 50:
            return "High"
        elif score >= 30:
            return "Medium"
        return "Low"

    def determine_tactic_categories(self, indicators: ThreatIndicators, findings: list) -> list:
        """공격 전술 분류"""
        tactics = []

        findings_text = " ".join(findings).lower()

        # Authority (권위 사칭)
        authority_keywords = ['정부', '은행', '공식', 'official', 'government', 'bank', 'verified']
        if any(kw in findings_text for kw in authority_keywords) or indicators.brand_impersonation:
            tactics.append("Authority")

        # Urgency (긴급성)
        if indicators.urgency_keywords_count > 0:
            tactics.append("Urgency")

        # Reward (보상 유혹)
        reward_keywords = ['경품', '당첨', '환급', '무료', 'prize', 'reward', 'free', 'gift', 'win']
        if any(kw in findings_text for kw in reward_keywords):
            tactics.append("Reward")

        # Fear (공포 유발)
        fear_keywords = ['정지', '차단', '만료', '해킹', 'suspend', 'block', 'expire', 'hack', 'compromised']
        if any(kw in findings_text for kw in fear_keywords):
            tactics.append("Fear")

        return tactics if tactics else ["Unknown"]

    def generate_llm_summary(self, report: LawEnforcementReport) -> str:
        """3줄 요약 생성 (LLM 스타일)"""
        lines = []

        # Line 1: 위협 유형 및 타겟
        if report.target_brand:
            lines.append(f"[{report.threat_level}] '{report.target_brand}' 브랜드를 사칭하는 피싱 사이트 탐지")
        else:
            lines.append(f"[{report.threat_level}] 의심스러운 피싱 사이트 탐지")

        # Line 2: 주요 공격 기법
        techniques = []
        if report.threat_indicators.homograph_detected:
            techniques.append("유사문자 공격")
        if report.threat_indicators.typosquatting_detected:
            techniques.append("오타 도메인")
        if report.threat_indicators.suspicious_tld:
            techniques.append("의심 TLD")
        if report.threat_indicators.brand_impersonation:
            techniques.append("브랜드 사칭")

        if techniques:
            lines.append(f"사용된 기법: {', '.join(techniques)}")
        else:
            lines.append("일반적인 피싱 패턴 탐지")

        # Line 3: 전술 및 권고
        tactics = ", ".join(report.tactic_category)
        lines.append(f"공격 전술: {tactics}. 즉시 접속 차단 및 도메인 등록기관 신고 권고")

        return "\n".join(lines)

    def create_report(
        self,
        url: str,
        spoofing_result=None,
        quadrant_report: dict = None,
        technical_info: dict = None,
        user_identifier: str = ""
    ) -> LawEnforcementReport:
        """전체 리포트 생성"""

        report = LawEnforcementReport()
        report.report_id = self.generate_report_id()
        report.report_timestamp = datetime.now().isoformat()

        # URL 정보 (익명화)
        report.suspicious_url = self.anonymizer.sanitize_url_for_sharing(url)

        # 스푸핑 결과 처리
        if spoofing_result:
            report.target_brand = spoofing_result.target_brand

            # 위협 지표 설정
            report.threat_indicators.homograph_detected = bool(spoofing_result.homograph_attacks)
            report.threat_indicators.typosquatting_detected = bool(spoofing_result.typosquatting)
            report.threat_indicators.suspicious_tld = spoofing_result.suspicious_tld
            report.threat_indicators.brand_impersonation = bool(spoofing_result.brand_abuse)
            report.threat_indicators.urgency_keywords_count = len(spoofing_result.urgency_signals)
            report.threat_indicators.trust_manipulation_count = len(spoofing_result.trust_manipulation)

            # 상세 발견 사항
            if spoofing_result.homograph_attacks:
                for attack in spoofing_result.homograph_attacks:
                    report.detailed_findings.append(f"유사문자 공격: {attack.get('description', '')}")
            if spoofing_result.brand_abuse:
                for abuse in spoofing_result.brand_abuse:
                    report.detailed_findings.append(f"브랜드 남용: '{abuse.get('keyword', '')}' in {abuse.get('location', '')}")

        # 4-Quadrant 보고서 처리
        if quadrant_report:
            report.quadrant_intent = quadrant_report.get('intent', {}).get('findings', [])
            report.quadrant_action = quadrant_report.get('action', {}).get('findings', [])
            report.quadrant_psychology = quadrant_report.get('psychology', {}).get('findings', [])
            report.quadrant_result = quadrant_report.get('result', {}).get('findings', [])

        # 기술적 메타데이터
        if technical_info:
            report.technical_metadata = TechnicalMetadata(
                domain=technical_info.get('domain', ''),
                ip_address=technical_info.get('ip_address'),
                registrar=technical_info.get('registrar'),
                domain_created=technical_info.get('domain_created'),
                ssl_issuer=technical_info.get('ssl_issuer'),
                redirect_chain=technical_info.get('redirect_chain', [])
            )
        else:
            # URL에서 기본 정보 추출
            parsed = urlparse(url)
            report.technical_metadata.domain = parsed.netloc

        # 위협 수준 결정
        report.threat_level = self.determine_threat_level(report.threat_indicators)

        # 전술 분류
        report.tactic_category = self.determine_tactic_categories(
            report.threat_indicators,
            report.detailed_findings
        )

        # LLM 요약 생성
        report.llm_summary = self.generate_llm_summary(report)

        # 익명 신고자 해시
        if user_identifier:
            report.anonymous_reporter_hash = self.anonymizer.generate_anonymous_id(user_identifier)

        return report

    def to_json(self, report: LawEnforcementReport) -> str:
        """리포트를 JSON 문자열로 변환"""
        def convert(obj):
            if hasattr(obj, '__dataclass_fields__'):
                return asdict(obj)
            return obj

        report_dict = asdict(report)
        return json.dumps(report_dict, ensure_ascii=False, indent=2, default=str)

    def to_markdown(self, report: LawEnforcementReport) -> str:
        """리포트를 마크다운 문자열로 변환"""
        md = f"""# 피싱 사이트 신고 리포트

## 기본 정보
| 항목 | 내용 |
|------|------|
| **리포트 ID** | `{report.report_id}` |
| **생성 일시** | {report.report_timestamp} |
| **위협 수준** | **{report.threat_level}** |
| **공격 전술** | {', '.join(report.tactic_category)} |

## AI 분석 요약
```
{report.llm_summary}
```

## 의심 URL 정보
- **URL**: `{report.suspicious_url}`
- **타겟 브랜드**: {report.target_brand or '미확인'}

## 기술적 메타데이터
| 항목 | 내용 |
|------|------|
| 도메인 | {report.technical_metadata.domain} |
| IP 주소 | {report.technical_metadata.ip_address or '미확인'} |
| 등록기관 | {report.technical_metadata.registrar or '미확인'} |
| 도메인 생성일 | {report.technical_metadata.domain_created or '미확인'} |
| SSL 발급자 | {report.technical_metadata.ssl_issuer or '미확인'} |

## 위협 지표
| 지표 | 탐지 |
|------|------|
| 유사문자 공격 | {'✓ 탐지됨' if report.threat_indicators.homograph_detected else '✗ 미탐지'} |
| 타이포스쿼팅 | {'✓ 탐지됨' if report.threat_indicators.typosquatting_detected else '✗ 미탐지'} |
| 의심 TLD | {'✓ 탐지됨' if report.threat_indicators.suspicious_tld else '✗ 미탐지'} |
| 브랜드 사칭 | {'✓ 탐지됨' if report.threat_indicators.brand_impersonation else '✗ 미탐지'} |
| 긴급성 유발 키워드 | {report.threat_indicators.urgency_keywords_count}개 |
| 신뢰 조작 키워드 | {report.threat_indicators.trust_manipulation_count}개 |

## 4-Quadrant 분석

### 🎯 Intent (의도)
{chr(10).join('- ' + f for f in report.quadrant_intent) if report.quadrant_intent else '- 분석 데이터 없음'}

### ⚡ Action (행위)
{chr(10).join('- ' + f for f in report.quadrant_action) if report.quadrant_action else '- 분석 데이터 없음'}

### 🧠 Psychology (심리)
{chr(10).join('- ' + f for f in report.quadrant_psychology) if report.quadrant_psychology else '- 분석 데이터 없음'}

### 📊 Result (결과)
{chr(10).join('- ' + f for f in report.quadrant_result) if report.quadrant_result else '- 분석 데이터 없음'}

## 상세 발견 사항
{chr(10).join('- ' + f for f in report.detailed_findings) if report.detailed_findings else '- 추가 발견 사항 없음'}

---

## 권고 조치
1. 해당 URL 접속 즉시 차단
2. 도메인 등록기관({report.technical_metadata.registrar or '미확인'})에 신고
3. 피해자 발생 시 경찰청 사이버수사대 연계
4. 금융 정보 유출 우려 시 금융감독원(1332) 신고

---

*본 리포트는 안다(An-Da)(anda) AI 시스템에 의해 자동 생성되었습니다.*
*리포트 ID: {report.report_id}*
*익명 신고자 ID: {report.anonymous_reporter_hash or 'N/A'}*
"""
        return md


# PDF 생성 함수 (HTML 기반)
def generate_pdf_html(report: LawEnforcementReport) -> str:
    """PDF 출력용 HTML 생성"""

    threat_color = {
        'Critical': '#ff4757',
        'High': '#ff6b6b',
        'Medium': '#ffa502',
        'Low': '#2ed573'
    }.get(report.threat_level, '#666')

    html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>피싱 사이트 신고 리포트 - {report.report_id}</title>
    <style>
        body {{
            font-family: 'Malgun Gothic', 'Apple SD Gothic Neo', sans-serif;
            margin: 40px;
            color: #333;
            line-height: 1.6;
        }}
        .header {{
            background: linear-gradient(135deg, #1a1a2e, #16213e);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            margin: 0;
            color: #00d4ff;
        }}
        .header .subtitle {{
            color: #888;
            margin-top: 10px;
        }}
        .threat-badge {{
            display: inline-block;
            background: {threat_color};
            color: white;
            padding: 8px 20px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 1.2em;
        }}
        .section {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            border-left: 4px solid #00d4ff;
        }}
        .section h2 {{
            color: #1a1a2e;
            margin-top: 0;
            border-bottom: 2px solid #00d4ff;
            padding-bottom: 10px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 10px 0;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
        }}
        th {{
            background: #1a1a2e;
            color: white;
        }}
        .summary-box {{
            background: #1a1a2e;
            color: white;
            padding: 20px;
            border-radius: 8px;
            font-family: monospace;
            white-space: pre-line;
        }}
        .quadrant-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
        }}
        .quadrant-box {{
            padding: 15px;
            border-radius: 8px;
            background: white;
            border: 1px solid #ddd;
        }}
        .quadrant-box.intent {{ border-left: 4px solid #ff6b6b; }}
        .quadrant-box.action {{ border-left: 4px solid #ffd93d; }}
        .quadrant-box.psychology {{ border-left: 4px solid #6bcb77; }}
        .quadrant-box.result {{ border-left: 4px solid #4d96ff; }}
        .quadrant-title {{
            font-weight: bold;
            margin-bottom: 10px;
        }}
        .footer {{
            text-align: center;
            color: #888;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
        }}
        .warning {{
            background: #fff3cd;
            border: 1px solid #ffc107;
            padding: 15px;
            border-radius: 8px;
            margin: 20px 0;
        }}
        .check-yes {{ color: #2ed573; }}
        .check-no {{ color: #999; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ 피싱 사이트 신고 리포트</h1>
        <p class="subtitle">anda AI 자동 분석 리포트</p>
        <p>리포트 ID: <strong>{report.report_id}</strong></p>
        <p>생성 일시: {report.report_timestamp}</p>
    </div>

    <div class="section">
        <h2>위협 수준</h2>
        <span class="threat-badge">{report.threat_level}</span>
        <p style="margin-top: 15px;"><strong>공격 전술:</strong> {', '.join(report.tactic_category)}</p>
    </div>

    <div class="section">
        <h2>AI 분석 요약</h2>
        <div class="summary-box">{report.llm_summary}</div>
    </div>

    <div class="section">
        <h2>의심 URL 정보</h2>
        <table>
            <tr><th>항목</th><th>내용</th></tr>
            <tr><td>URL</td><td><code>{report.suspicious_url}</code></td></tr>
            <tr><td>타겟 브랜드</td><td>{report.target_brand or '미확인'}</td></tr>
            <tr><td>도메인</td><td>{report.technical_metadata.domain}</td></tr>
            <tr><td>등록기관</td><td>{report.technical_metadata.registrar or '미확인'}</td></tr>
            <tr><td>도메인 생성일</td><td>{report.technical_metadata.domain_created or '미확인'}</td></tr>
        </table>
    </div>

    <div class="section">
        <h2>위협 지표</h2>
        <table>
            <tr><th>지표</th><th>탐지 결과</th></tr>
            <tr>
                <td>유사문자 공격 (Homograph)</td>
                <td class="{'check-yes' if report.threat_indicators.homograph_detected else 'check-no'}">
                    {'✓ 탐지됨' if report.threat_indicators.homograph_detected else '✗ 미탐지'}
                </td>
            </tr>
            <tr>
                <td>타이포스쿼팅</td>
                <td class="{'check-yes' if report.threat_indicators.typosquatting_detected else 'check-no'}">
                    {'✓ 탐지됨' if report.threat_indicators.typosquatting_detected else '✗ 미탐지'}
                </td>
            </tr>
            <tr>
                <td>의심 TLD</td>
                <td class="{'check-yes' if report.threat_indicators.suspicious_tld else 'check-no'}">
                    {'✓ 탐지됨' if report.threat_indicators.suspicious_tld else '✗ 미탐지'}
                </td>
            </tr>
            <tr>
                <td>브랜드 사칭</td>
                <td class="{'check-yes' if report.threat_indicators.brand_impersonation else 'check-no'}">
                    {'✓ 탐지됨' if report.threat_indicators.brand_impersonation else '✗ 미탐지'}
                </td>
            </tr>
            <tr><td>긴급성 유발 키워드</td><td>{report.threat_indicators.urgency_keywords_count}개</td></tr>
            <tr><td>신뢰 조작 키워드</td><td>{report.threat_indicators.trust_manipulation_count}개</td></tr>
        </table>
    </div>

    <div class="section">
        <h2>4-Quadrant 분석</h2>
        <div class="quadrant-grid">
            <div class="quadrant-box intent">
                <div class="quadrant-title">🎯 Intent (의도)</div>
                <ul>{''.join(f'<li>{f}</li>' for f in report.quadrant_intent) if report.quadrant_intent else '<li>분석 데이터 없음</li>'}</ul>
            </div>
            <div class="quadrant-box action">
                <div class="quadrant-title">⚡ Action (행위)</div>
                <ul>{''.join(f'<li>{f}</li>' for f in report.quadrant_action) if report.quadrant_action else '<li>분석 데이터 없음</li>'}</ul>
            </div>
            <div class="quadrant-box psychology">
                <div class="quadrant-title">🧠 Psychology (심리)</div>
                <ul>{''.join(f'<li>{f}</li>' for f in report.quadrant_psychology) if report.quadrant_psychology else '<li>분석 데이터 없음</li>'}</ul>
            </div>
            <div class="quadrant-box result">
                <div class="quadrant-title">📊 Result (결과)</div>
                <ul>{''.join(f'<li>{f}</li>' for f in report.quadrant_result) if report.quadrant_result else '<li>분석 데이터 없음</li>'}</ul>
            </div>
        </div>
    </div>

    <div class="warning">
        <h3>⚠️ 권고 조치</h3>
        <ol>
            <li>해당 URL 접속 즉시 차단</li>
            <li>도메인 등록기관({report.technical_metadata.registrar or '확인 필요'})에 신고</li>
            <li>피해자 발생 시 경찰청 사이버수사대 연계</li>
            <li>금융 정보 유출 우려 시 금융감독원(1332) 신고</li>
        </ol>
    </div>

    <div class="footer">
        <p>본 리포트는 <strong>안다(An-Da)(anda)</strong> AI 시스템에 의해 자동 생성되었습니다.</p>
        <p>리포트 ID: {report.report_id} | 익명 신고자 ID: {report.anonymous_reporter_hash or 'N/A'}</p>
    </div>
</body>
</html>
"""
    return html


# 싱글톤 인스턴스
_generator_instance = None


def get_report_generator() -> ReportGenerator:
    """리포트 생성기 싱글톤 인스턴스 반환"""
    global _generator_instance
    if _generator_instance is None:
        _generator_instance = ReportGenerator()
    return _generator_instance
