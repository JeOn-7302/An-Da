"""
안다 (An-da) - AI 피싱 탐지 서비스
사용자 뷰 + 경찰 관제 뷰 통합
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import json
import time
import asyncio
from datetime import datetime
from pathlib import Path
import sys

# 프로젝트 루트 경로 추가
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.database import get_database
from src.spoofing_detector import get_spoofing_detector, SpoofingResult
from src.law_enforcement import get_report_generator, generate_pdf_html
from src.unified_analyzer import get_unified_analyzer, UnifiedAnalysisResult, AnalysisLayer

# 페이지 설정
st.set_page_config(
    page_title="안다 (An-da) - AI 피싱 탐지",
    page_icon=None,
    layout="wide",
    initial_sidebar_state="expanded"
)

# 로고 이미지 경로
LOGO_PATH = Path(__file__).parent.parent / "data" / "logo.png"

# 시뮬레이션 데이터 경로
SIMULATION_DIR = Path(__file__).parent.parent / "data" / "simulations"
SIMULATION_DIR.mkdir(parents=True, exist_ok=True)

# 시뮬레이션용 예시 데이터
SIMULATION_DATA = {
    "naver_phishing": {
        "url": "https://naver-login-security.com/verify",
        "is_phishing": True,
        "risk_score": 0.92,
        "detected_brand": "naver",
        "reason": [
            "[위험] 'naver' 사이트와 94.2% 유사하나 공식 도메인이 아님",
            "'naver' 키워드를 포함한 비공식 도메인",
            "URL 패턴 분석 결과 피싱 의심 (확률: 87.3%)",
            "도메인 생성일: 7일 전 (신규 도메인)"
        ],
        "visual_similarity": 0.942,
        "url_phishing_prob": 0.873,
        "domain_created": "2024-01-23",
        "whois_registrar": "NameCheap Inc."
    },
    "kakao_phishing": {
        "url": "https://kakaotalk-gift.event-page.com/win",
        "is_phishing": True,
        "risk_score": 0.88,
        "detected_brand": "kakao",
        "reason": [
            "[위험] 'kakao' 사이트와 91.5% 유사하나 공식 도메인이 아님",
            "'kakao' 키워드를 포함한 비공식 도메인",
            "과도한 서브도메인 사용",
            "의심스러운 이벤트/경품 페이지"
        ],
        "visual_similarity": 0.915,
        "url_phishing_prob": 0.812,
        "domain_created": "2024-01-20",
        "whois_registrar": "GoDaddy"
    },
    "government_phishing": {
        "url": "https://gov-kr-tax-refund.com/claim",
        "is_phishing": True,
        "risk_score": 0.95,
        "detected_brand": "government",
        "reason": [
            "[위험] 정부 사이트와 96.1% 유사하나 공식 도메인(.go.kr)이 아님",
            "'gov' 키워드를 포함한 비공식 도메인",
            "세금 환급 사칭 피싱 패턴",
            "HTTPS 인증서 발급일: 3일 전"
        ],
        "visual_similarity": 0.961,
        "url_phishing_prob": 0.923,
        "domain_created": "2024-01-27",
        "whois_registrar": "Namecheap"
    },
    "safe_naver": {
        "url": "https://www.naver.com",
        "is_phishing": False,
        "risk_score": 0.02,
        "detected_brand": "naver",
        "reason": [
            "[안전] 공식 도메인 확인됨: naver",
            "SSL 인증서 유효",
            "도메인 등록 20년 이상"
        ],
        "visual_similarity": 1.0,
        "url_phishing_prob": 0.01,
        "domain_created": "1999-06-08",
        "whois_registrar": "Gabia Inc."
    }
}


def load_custom_css():
    """커스텀 CSS 로드"""
    st.markdown("""
    <style>
        /* 메인 헤더 */
        .main-header {
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            padding: 2rem;
            border-radius: 1rem;
            text-align: center;
            margin-bottom: 2rem;
        }
        .main-header h1 {
            color: #00d4ff;
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
        }
        .main-header p {
            color: #888;
        }

        /* 경고 화면 */
        .danger-screen {
            background: linear-gradient(135deg, #ff416c 0%, #ff4b2b 100%);
            padding: 3rem;
            border-radius: 1rem;
            text-align: center;
            color: white;
            animation: pulse 2s infinite;
        }
        .safe-screen {
            background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
            padding: 3rem;
            border-radius: 1rem;
            text-align: center;
            color: white;
        }
        @keyframes pulse {
            0% { box-shadow: 0 0 0 0 rgba(255, 65, 108, 0.7); }
            70% { box-shadow: 0 0 0 20px rgba(255, 65, 108, 0); }
            100% { box-shadow: 0 0 0 0 rgba(255, 65, 108, 0); }
        }

        /* 카드 스타일 */
        .metric-card {
            background: #1e2a4a;
            padding: 1.5rem;
            border-radius: 1rem;
            text-align: center;
            border: 1px solid #0f3460;
        }
        .metric-card h3 {
            color: #00d4ff;
            margin-bottom: 0.5rem;
        }
        .metric-card .value {
            font-size: 2rem;
            font-weight: bold;
            color: white;
        }

        /* 비교 뷰 */
        .comparison-box {
            background: #1e2a4a;
            padding: 1rem;
            border-radius: 0.5rem;
            border: 2px solid #0f3460;
        }
        .comparison-box.fake {
            border-color: #ff4757;
        }
        .comparison-box.real {
            border-color: #2ed573;
        }

        /* 시뮬레이션 버튼 */
        .sim-button {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 1rem 2rem;
            border-radius: 0.5rem;
            border: none;
            cursor: pointer;
            margin: 0.5rem;
        }

        /* 로고 이미지 투명 배경 처리 */
        [data-testid="stImage"] img {
            background: transparent !important;
        }

        /* 사이드바 로고 */
        [data-testid="stSidebar"] [data-testid="stImage"] img {
            background: transparent !important;
        }
    </style>
    """, unsafe_allow_html=True)


def show_user_view():
    """사용자(고령층) 뷰 - 단순한 경고/안전 화면"""
    # 로고와 서비스명 표시
    col_logo, col_title = st.columns([1, 5])
    with col_logo:
        if LOGO_PATH.exists():
            st.image(str(LOGO_PATH), width=280)
    with col_title:
        st.markdown("""
        <div style="padding-top: 1rem;">
            <h1 style="color: #001960; margin-bottom: 0.2rem;">안다 (An-da)</h1>
            <p style="color: #888; font-size: 1.1rem;">가짜 사이트 탐지 AI 서비스</p>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")

    st.markdown("### 의심되는 사이트 주소를 입력해주세요")

    col1, col2 = st.columns([4, 1])
    with col1:
        url_input = st.text_input(
            "URL 입력",
            placeholder="예: https://naver-login.suspicious.com",
            label_visibility="collapsed"
        )
    with col2:
        analyze_btn = st.button("검사하기", width='stretch', type="primary")

    st.markdown("---")

    # 시뮬레이션 예시 버튼
    st.markdown("#### 예시 버튼 (시뮬레이션)")
    sim_col1, sim_col2, sim_col3, sim_col4 = st.columns(4)

    with sim_col1:
        if st.button("네이버 피싱", width='stretch'):
            st.session_state.simulation = "naver_phishing"
    with sim_col2:
        if st.button("카카오 피싱", width='stretch'):
            st.session_state.simulation = "kakao_phishing"
    with sim_col3:
        if st.button("정부 사칭", width='stretch'):
            st.session_state.simulation = "government_phishing"
    with sim_col4:
        if st.button("정상 사이트", width='stretch'):
            st.session_state.simulation = "safe_naver"

    # 분석 실행
    result = None
    unified_result = None

    if analyze_btn and url_input:
        # AI 분석 단계 표시 (고령층 친화적 큰 글씨)
        st.markdown("---")
        st.markdown("### AI가 분석하고 있어요")

        # 분석 단계 카드
        col_ai1, col_ai2, col_ai3 = st.columns(3)

        with col_ai1:
            step1_placeholder = st.empty()
            step1_placeholder.markdown("""
            <div style="background: #1e3a5f; padding: 1rem; border-radius: 0.5rem; text-align: center;">
                <p style="color: #ffd93d; font-size: 1.5rem; margin: 0;">...</p>
                <p style="color: white; font-size: 1.1rem; margin: 0.5rem 0 0 0;">규칙 기반 탐지</p>
            </div>
            """, unsafe_allow_html=True)

        with col_ai2:
            step2_placeholder = st.empty()
            step2_placeholder.markdown("""
            <div style="background: #2d2d5a; padding: 1rem; border-radius: 0.5rem; text-align: center;">
                <p style="color: #888; font-size: 1.5rem; margin: 0;">-</p>
                <p style="color: #888; font-size: 1.1rem; margin: 0.5rem 0 0 0;">BERT AI 분석</p>
            </div>
            """, unsafe_allow_html=True)

        with col_ai3:
            step3_placeholder = st.empty()
            step3_placeholder.markdown("""
            <div style="background: #2d2d5a; padding: 1rem; border-radius: 0.5rem; text-align: center; border: 1px dashed #666;">
                <p style="color: #666; font-size: 1.5rem; margin: 0;">-</p>
                <p style="color: #666; font-size: 1.1rem; margin: 0.5rem 0 0 0;">LLM 분석 (준비중)</p>
            </div>
            """, unsafe_allow_html=True)

        progress_bar = st.progress(0)

        # Step 1: 규칙 기반 분석
        time.sleep(0.5)
        progress_bar.progress(33)
        step1_placeholder.markdown("""
        <div style="background: #11998e; padding: 1rem; border-radius: 0.5rem; text-align: center;">
            <p style="color: white; font-size: 1.5rem; margin: 0;">OK</p>
            <p style="color: white; font-size: 1.1rem; margin: 0.5rem 0 0 0;">규칙 기반 탐지</p>
        </div>
        """, unsafe_allow_html=True)

        # Step 2: BERT 분석
        step2_placeholder.markdown("""
        <div style="background: #1e3a5f; padding: 1rem; border-radius: 0.5rem; text-align: center;">
            <p style="color: #ffd93d; font-size: 1.5rem; margin: 0;">...</p>
            <p style="color: white; font-size: 1.1rem; margin: 0.5rem 0 0 0;">BERT AI 분석</p>
        </div>
        """, unsafe_allow_html=True)

        # 실제 통합 분석 실행
        analyzer = get_unified_analyzer(enable_bert=True, enable_llm=False)
        unified_result = analyzer.analyze(url_input)

        progress_bar.progress(66)
        step2_placeholder.markdown("""
        <div style="background: #11998e; padding: 1rem; border-radius: 0.5rem; text-align: center;">
            <p style="color: white; font-size: 1.5rem; margin: 0;">OK</p>
            <p style="color: white; font-size: 1.1rem; margin: 0.5rem 0 0 0;">BERT AI 분석</p>
        </div>
        """, unsafe_allow_html=True)

        time.sleep(0.3)
        progress_bar.progress(100)
        time.sleep(0.3)
        progress_bar.empty()

        # 결과를 기존 형식으로 변환
        result = {
            "url": url_input,
            "is_phishing": unified_result.is_phishing,
            "risk_score": unified_result.final_confidence,
            "detected_brand": unified_result.detected_brand,  # None 유지, 표시 시점에서 fallback
            "reason": [],
            "unified_result": unified_result  # 상세 분석용
        }

        # 탐지 이유 생성
        for layer_result in unified_result.layer_results:
            if layer_result.is_dangerous and layer_result.reason:
                if layer_result.layer == AnalysisLayer.RULE_BASED:
                    result["reason"].append(f"[규칙] {layer_result.reason}")
                elif layer_result.layer == AnalysisLayer.BERT_ML:
                    result["reason"].append(f"[AI] {layer_result.reason}")

        if unified_result.is_phishing and not result["reason"]:
            result["reason"].append("[위험] 피싱 사이트로 의심됩니다")
        elif not unified_result.is_phishing:
            result["reason"] = ["[안전] 안전한 것으로 판단됩니다"]

        # 데이터베이스에 분석 결과 저장
        # 개인정보 보호 정책:
        # - 전체 분석 건수: 익명 카운터로만 저장 (URL, 사용자 정보 없음)
        # - 피싱 탐지: 상세 정보 저장 (경찰 조치용)
        # - 안전 판정: URL 및 상세정보 저장 안 함 (사생활 보호)
        db = get_database()

        # 전체 분석 건수만 익명으로 카운트 (is_safe=True면 안전 판정 카운트도 증가)
        db.increment_analysis_count(is_safe=not unified_result.is_phishing)

        # 피싱으로 탐지된 경우에만 상세 정보 저장 (경찰 관제용)
        if unified_result.is_phishing:
            from urllib.parse import urlparse
            parsed_url = urlparse(url_input if url_input.startswith(("http://", "https://")) else f"https://{url_input}")
            domain = parsed_url.netloc.lower()
            if domain.startswith("www."):
                domain = domain[4:]

            analysis_id = db.save_analysis(
                url=url_input,
                domain=domain,
                is_phishing=True,
                risk_score=unified_result.final_confidence,
                detected_brand=unified_result.detected_brand,
                screenshot_path=None
            )
            ai_reasoning = " | ".join(result["reason"]) if result["reason"] else "피싱 의심"
            suspicious_patterns = []

            # 레이어별 상세 정보 수집
            url_phishing_prob = 0.0
            for layer_result in unified_result.layer_results:
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

            db.save_phishing_detail(
                analysis_id=analysis_id,
                impersonated_brand=unified_result.detected_brand or "unknown",
                ai_reasoning=ai_reasoning,
                url_phishing_prob=url_phishing_prob,
                visual_similarity=0.0,  # 현재 시각 분석 미사용
                suspicious_patterns=suspicious_patterns
            )
        # 안전한 URL은 저장하지 않음 - 개인정보 보호

    # 시뮬레이션 결과 표시
    if "simulation" in st.session_state:
        result = SIMULATION_DATA[st.session_state.simulation]
        spoofing_result = None  # 시뮬레이션은 spoofing_result 없음
        del st.session_state.simulation

    # 결과 표시
    if result:
        st.markdown("---")

        if result["is_phishing"]:
            # 위험 화면 (큰 글씨, 단순한 메시지)
            brand_name = result["detected_brand"] or "알 수 없는"
            st.markdown(f"""
            <div class="danger-screen">
                <h1 style="font-size: 5rem;">위험!</h1>
                <h2 style="font-size: 2.5rem;">가짜 사이트입니다!</h2>
                <p style="font-size: 1.8rem; margin-top: 1rem;">
                    <strong>'{brand_name}'</strong> 사이트를 흉내낸 사기 사이트예요
                </p>
                <div style="background: rgba(0,0,0,0.4); padding: 1.5rem; border-radius: 1rem; margin-top: 2rem;">
                    <p style="font-size: 1.5rem; margin: 0.5rem 0;">
                        <strong>개인정보 입력 금지!</strong>
                    </p>
                    <p style="font-size: 1.5rem; margin: 0.5rem 0;">
                        <strong>지금 바로 창을 닫으세요!</strong>
                    </p>
                </div>
            </div>
            """, unsafe_allow_html=True)

            # 신고 안내 (큰 버튼)
            st.markdown("<br>", unsafe_allow_html=True)
            st.markdown("### 피해를 당하셨나요?")

            col1, col2 = st.columns(2)
            with col1:
                st.markdown("""
                <div style="background: #1e3a5f; padding: 1.5rem; border-radius: 1rem; text-align: center;">
                    <p style="font-size: 1.3rem; color: white; margin-bottom: 0.5rem;">경찰청 사이버수사대</p>
                    <p style="font-size: 2.5rem; color: #00d4ff; font-weight: bold;">182</p>
                </div>
                """, unsafe_allow_html=True)
            with col2:
                st.markdown("""
                <div style="background: #1e3a5f; padding: 1.5rem; border-radius: 1rem; text-align: center;">
                    <p style="font-size: 1.3rem; color: white; margin-bottom: 0.5rem;">금융감독원</p>
                    <p style="font-size: 2.5rem; color: #00d4ff; font-weight: bold;">1332</p>
                </div>
                """, unsafe_allow_html=True)

            st.markdown("<br><br>", unsafe_allow_html=True)

            # 상세 정보 (접이식 - 관심있는 분만)
            with st.expander("상세 분석 결과 보기"):
                for reason in result["reason"]:
                    st.warning(reason)

                # AI 분석 상세 (unified_result가 있을 때)
                if "unified_result" in result and result["unified_result"]:
                    unified = result["unified_result"]
                    st.markdown("---")
                    st.markdown("#### AI 분석 상세")

                    # 레이어별 결과 표시
                    for layer_result in unified.layer_results:
                        if layer_result.layer == AnalysisLayer.RULE_BASED:
                            name = "규칙 기반 탐지"
                        elif layer_result.layer == AnalysisLayer.BERT_ML:
                            name = "BERT AI 모델"
                        else:
                            name = "LLM 분석"

                        status_color = "#ff6b6b" if layer_result.is_dangerous else "#2ed573"
                        status_text = "위험" if layer_result.is_dangerous else "안전"

                        st.markdown(f"""
                        <div style="background: rgba(30,40,70,0.8); padding: 1rem; border-radius: 0.5rem; margin: 0.5rem 0; border-left: 4px solid {status_color};">
                            <p style="color: white; margin: 0;"><strong>{name}</strong></p>
                            <p style="color: {status_color}; margin: 0.3rem 0;">판정: {status_text} (신뢰도: {layer_result.confidence*100:.0f}%)</p>
                            <p style="color: #aaa; margin: 0; font-size: 0.9rem;">{layer_result.reason}</p>
                        </div>
                        """, unsafe_allow_html=True)

                    # LLM 향후 지원 안내
                    st.markdown("""
                    <div style="background: rgba(100,100,150,0.3); padding: 1rem; border-radius: 0.5rem; margin-top: 1rem; border: 1px dashed #666;">
                        <p style="color: #aaa; margin: 0;"><strong>LLM 의도 분석</strong> - 향후 지원 예정</p>
                        <p style="color: #888; margin: 0.3rem 0 0 0; font-size: 0.85rem;">
                            GPT/Claude API를 연동하여 더 정교한 피싱 의도 분석을 제공할 예정입니다.
                        </p>
                    </div>
                    """, unsafe_allow_html=True)

                # 경찰 신고용 리포트 다운로드 (unified_result가 있을 때)
                if "unified_result" in result and result["unified_result"]:
                    st.markdown("---")
                    st.markdown("#### 경찰 신고용 자료")
                    generator = get_report_generator()
                    # unified_result에서 spoofing 정보 추출
                    spoofing_detector = get_spoofing_detector()
                    spoofing_result = spoofing_detector.analyze(result["url"])
                    report = generator.create_report(url=result["url"], spoofing_result=spoofing_result)

                    col_a, col_b = st.columns(2)
                    with col_a:
                        pdf_html = generate_pdf_html(report)
                        st.download_button(
                            label="신고서 다운로드 (출력용)",
                            data=pdf_html,
                            file_name=f"신고서_{report.report_id}.html",
                            mime="text/html",
                            width='stretch'
                        )
                    with col_b:
                        json_report = generator.to_json(report)
                        st.download_button(
                            label="증거자료 다운로드",
                            data=json_report,
                            file_name=f"증거자료_{report.report_id}.json",
                            mime="application/json",
                            width='stretch'
                        )

        else:
            # 안전 화면 (큰 글씨, 안심 메시지)
            brand_name = result["detected_brand"] or "확인된"
            st.markdown(f"""
            <div class="safe-screen">
                <h1 style="font-size: 5rem;">안전!</h1>
                <h2 style="font-size: 2.5rem;">공식 사이트입니다</h2>
                <p style="font-size: 1.8rem; margin-top: 1rem;">
                    <strong>'{brand_name}'</strong> 진짜 사이트예요
                </p>
                <p style="font-size: 1.5rem; margin-top: 2rem;">
                    안심하고 이용하세요
                </p>
            </div>
            """, unsafe_allow_html=True)


def show_police_view():
    """경찰 관제 뷰 - 상세 분석 대시보드"""
    # 로고와 서비스명 표시
    col_logo, col_title = st.columns([1, 5])
    with col_logo:
        if LOGO_PATH.exists():
            st.image(str(LOGO_PATH), width=280)
    with col_title:
        st.markdown("""
        <div style="padding-top: 0.5rem;">
            <h1 style="color: #001960; margin-bottom: 0.2rem;">안다 (An-da) 관제 센터</h1>
            <p style="color: #888;">경찰청 피싱 사이트 모니터링 대시보드</p>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")

    # 탭 구성
    tab1, tab2, tab3, tab4 = st.tabs(["대시보드", "상세 분석", "신고 리포트", "브랜드 관리"])

    with tab1:
        show_dashboard_tab()

    with tab2:
        show_analysis_tab()

    with tab3:
        show_report_tab()

    with tab4:
        show_brand_management_tab()


def show_dashboard_tab():
    """대시보드 탭"""
    # 통계 카드
    col1, col2, col3, col4 = st.columns(4)

    db = get_database()
    stats = db.get_statistics()

    with col1:
        st.metric("전체 분석", f"{stats['total_analyses']:,}건")
    with col2:
        st.metric("피싱 탐지", f"{stats['phishing_detected']:,}건", delta=f"{stats['detection_rate']*100:.1f}%")
    with col3:
        st.metric("평균 위험도", f"{stats['average_risk_score']*100:.1f}%")
    with col4:
        st.metric("사칭 브랜드", f"{len(stats.get('brand_statistics', []))}개")

    st.markdown("---")

    # 최근 탐지된 피싱 사이트 목록
    st.subheader("최근 탐지된 피싱 사이트")
    phishing_cases = db.get_phishing_cases(limit=20)

    if phishing_cases:
        for case in phishing_cases[:5]:  # 상위 5건만 표시
            risk_color = "#ff4757" if case["risk_score"] >= 0.7 else "#ffa502" if case["risk_score"] >= 0.4 else "#2ed573"
            st.markdown(f"""
            <div style="background: #1e2a4a; padding: 1rem; border-radius: 0.5rem; margin-bottom: 0.5rem; border-left: 4px solid {risk_color};">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <p style="color: white; font-size: 1rem; margin: 0;"><strong>{case['url'][:60]}{'...' if len(case['url']) > 60 else ''}</strong></p>
                        <p style="color: #aaa; font-size: 0.85rem; margin: 0.3rem 0 0 0;">
                            사칭 브랜드: <span style="color: #ff6b6b;">{case.get('impersonated_brand') or case.get('detected_brand') or 'unknown'}</span>
                            | 탐지 시각: {case['created_at']}
                        </p>
                    </div>
                    <div style="text-align: right;">
                        <p style="color: {risk_color}; font-size: 1.5rem; font-weight: bold; margin: 0;">{case['risk_score']*100:.0f}%</p>
                        <p style="color: #aaa; font-size: 0.75rem; margin: 0;">위험도</p>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)

        # 전체 목록 테이블로 표시
        with st.expander(f"전체 탐지 목록 보기 ({len(phishing_cases)}건)"):
            df_cases = pd.DataFrame([{
                "URL": case["url"][:50] + "..." if len(case["url"]) > 50 else case["url"],
                "사칭 브랜드": case.get("impersonated_brand") or case.get("detected_brand") or "-",
                "위험도": f"{case['risk_score']*100:.0f}%",
                "탐지 시각": case["created_at"],
                "AI 분석": case.get("ai_reasoning", "-")[:50] + "..." if case.get("ai_reasoning") and len(case.get("ai_reasoning", "")) > 50 else case.get("ai_reasoning", "-")
            } for case in phishing_cases])
            st.dataframe(df_cases, width='stretch')
    else:
        st.info("아직 탐지된 피싱 사이트가 없습니다. 사용자 화면에서 URL을 분석해보세요.")

    st.markdown("---")

    # 차트
    col_chart1, col_chart2 = st.columns(2)

    with col_chart1:
        st.subheader("사칭 브랜드 현황")
        brand_stats = stats.get("brand_statistics", [])
        if brand_stats:
            df = pd.DataFrame(brand_stats)
            fig = px.pie(df, values="count", names="brand", hole=0.4,
                        color_discrete_sequence=px.colors.qualitative.Set2)
            st.plotly_chart(fig, width='stretch')
        else:
            st.info("브랜드별 통계 데이터가 없습니다.")

    with col_chart2:
        st.subheader("일별 탐지 추이")
        daily_stats = stats.get("daily_statistics", [])
        if daily_stats:
            df = pd.DataFrame(daily_stats)
            fig = go.Figure()
            fig.add_trace(go.Scatter(x=df["date"], y=df["total"], name="전체",
                                    line=dict(color="#00d4ff")))
            fig.add_trace(go.Scatter(x=df["date"], y=df["phishing"], name="피싱",
                                    line=dict(color="#ff4757"), fill="tozeroy"))
            st.plotly_chart(fig, width='stretch')
        else:
            st.info("일별 통계 데이터가 없습니다.")


def show_analysis_tab():
    """상세 분석 탭 - 예시 이미지 기반 시각 유사도 데모"""
    st.subheader("시각 유사도 분석")

    # 예시 이미지 디렉토리
    examples_dir = Path(__file__).parent.parent / "data" / "examples"

    # 데모용 케이스 데이터
    DEMO_CASES = {
        "naver": {
            "name": "네이버 피싱 사례",
            "brand": "naver",
            "brand_display": "네이버",
            "phishing_url": "https://naver-login-security.com/verify",
            "phishing_domain": "naver-login-security.com",
            "official_url": "https://nid.naver.com",
            "visual_similarity": 0.942,
            "url_phishing_prob": 0.873,
            "risk_score": 0.92,
            "reasons": [
                "'naver' 키워드를 포함한 비공식 도메인",
                "URL 패턴 분석 결과 피싱 의심",
                "신규 등록 도메인 (7일 전)"
            ]
        },
        "kakao": {
            "name": "카카오 피싱 사례",
            "brand": "kakao",
            "brand_display": "카카오",
            "phishing_url": "https://kakaotalk-gift.event-page.com/win",
            "phishing_domain": "kakaotalk-gift.event-page.com",
            "official_url": "https://accounts.kakao.com",
            "visual_similarity": 0.915,
            "url_phishing_prob": 0.812,
            "risk_score": 0.88,
            "reasons": [
                "'kakao' 키워드를 포함한 비공식 도메인",
                "과도한 서브도메인 사용",
                "의심스러운 이벤트/경품 페이지"
            ]
        },
        "government": {
            "name": "정부 사칭 사례",
            "brand": "government",
            "brand_display": "정부24",
            "phishing_url": "https://gov-kr-tax-refund.com/claim",
            "phishing_domain": "gov-kr-tax-refund.com",
            "official_url": "https://www.gov.kr",
            "visual_similarity": 0.961,
            "url_phishing_prob": 0.923,
            "risk_score": 0.95,
            "reasons": [
                "정부 사이트 사칭 (.go.kr 아님)",
                "세금 환급 사칭 피싱 패턴",
                "신규 등록 도메인 (3일 전)"
            ]
        }
    }

    # 케이스 선택
    case_options = list(DEMO_CASES.keys())

    selected_key = st.selectbox(
        "분석 사례 선택",
        case_options,
        format_func=lambda x: DEMO_CASES[x]["name"]
    )

    case = DEMO_CASES[selected_key]

    st.markdown("---")

    # 케이스 상세 정보
    col_info1, col_info2 = st.columns(2)

    with col_info1:
        st.markdown(f"""
        <div style="background: #1e2a4a; padding: 1rem; border-radius: 0.5rem; border: 2px solid #ff4757;">
            <h4 style="color: #ff4757;">[피싱] 사이트 정보</h4>
            <p style="color: #fff; word-break: break-all;"><strong>URL:</strong> {case['phishing_url']}</p>
            <p style="color: #fff;"><strong>도메인:</strong> {case['phishing_domain']}</p>
            <p style="color: #fff;"><strong>사칭 브랜드:</strong> {case['brand_display']}</p>
        </div>
        """, unsafe_allow_html=True)

    with col_info2:
        st.markdown(f"""
        <div style="background: #1e2a4a; padding: 1rem; border-radius: 0.5rem; border: 2px solid #2ed573;">
            <h4 style="color: #2ed573;">[공식] 사이트 정보</h4>
            <p style="color: #fff;"><strong>브랜드:</strong> {case['brand_display']}</p>
            <p style="color: #fff;"><strong>공식 URL:</strong> {case['official_url']}</p>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")

    # 스크린샷 비교 섹션
    st.subheader("스크린샷 비교")

    col_ss1, col_ss2 = st.columns(2)

    # 예시 이미지 경로
    phishing_img_path = examples_dir / f"{case['brand']}_phishing.png"
    official_img_path = examples_dir / f"{case['brand']}_official.png"

    with col_ss1:
        st.markdown("**[피싱] 사이트**")
        if phishing_img_path.exists():
            st.image(str(phishing_img_path), caption="피싱 사이트 (예시)", use_container_width=True)
        else:
            st.markdown("""
            <div style="background: #2a2a3e; padding: 3rem; border-radius: 0.5rem; text-align: center; border: 1px dashed #ff4757;">
                <p style="color: #888;">예시 이미지 없음</p>
                <p style="color: #666; font-size: 0.8rem;">scripts/generate_sample_screenshots.py 실행 필요</p>
            </div>
            """, unsafe_allow_html=True)

    with col_ss2:
        st.markdown("**[공식] 사이트**")
        if official_img_path.exists():
            st.image(str(official_img_path), caption="공식 사이트 (예시)", use_container_width=True)
        else:
            st.markdown("""
            <div style="background: #2a2a3e; padding: 3rem; border-radius: 0.5rem; text-align: center; border: 1px dashed #2ed573;">
                <p style="color: #888;">예시 이미지 없음</p>
                <p style="color: #666; font-size: 0.8rem;">scripts/generate_sample_screenshots.py 실행 필요</p>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("---")

    # AI 분석 결과
    st.subheader("AI 분석 결과")

    col_m1, col_m2, col_m3 = st.columns(3)

    with col_m1:
        st.metric(
            "시각 유사도",
            f"{case['visual_similarity']*100:.1f}%",
            delta="90% 이상 = 사칭 의심"
        )
    with col_m2:
        st.metric("URL 피싱 확률", f"{case['url_phishing_prob']*100:.1f}%")
    with col_m3:
        st.metric(
            "종합 위험도",
            f"{case['risk_score']*100:.1f}%",
            delta="위험" if case['risk_score'] >= 0.7 else "주의"
        )

    # 탐지 근거
    st.markdown("**탐지 근거:**")
    for reason in case['reasons']:
        st.markdown(f"- {reason}")

    # 분석 방법 설명
    with st.expander("시각 유사도 분석 방법"):
        st.markdown("""
        **pHash (Perceptual Hash) - 40% 가중치**
        - 이미지의 전체적인 구조와 레이아웃 비교
        - 해상도나 압축에 강건한 해시 기반 비교

        **SSIM (Structural Similarity Index) - 60% 가중치**
        - 휘도, 대비, 구조적 유사성 측정
        - 인간의 시각적 인지와 유사한 비교 방식

        **종합 유사도 = pHash(40%) + SSIM(60%)**
        - 85% 이상: 높은 유사도 (사칭 의심)
        - 70-85%: 중간 유사도 (추가 검토 필요)
        - 70% 미만: 낮은 유사도
        """)


def _capture_reference_screenshot(brand: str, url: str):
    """공식 사이트 레퍼런스 스크린샷 캡처"""
    try:
        from src.screenshot_capture import get_screenshot_capture
        from src.visual_similarity import get_reference_manager

        with st.spinner("공식 사이트 스크린샷 캡처 중..."):
            capture = get_screenshot_capture()
            ref_manager = get_reference_manager()

            # 임시 캡처
            temp_path = capture.capture(url)

            if temp_path:
                # 레퍼런스로 저장
                ref_path = ref_manager.save_reference(brand, temp_path)
                st.success(f"레퍼런스 저장 완료: {ref_path}")
                st.rerun()
            else:
                st.error("스크린샷 캡처 실패")
    except ImportError:
        st.error("필요한 모듈이 설치되어 있지 않습니다.")
    except Exception as e:
        st.error(f"캡처 오류: {e}")


def show_brand_management_tab():
    """브랜드 관리 탭 - 브랜드 CRUD"""
    st.subheader("브랜드 관리")
    st.markdown("피싱 탐지에 사용되는 브랜드 정보를 관리합니다.")

    db = get_database()
    brands = db.get_all_brands(include_inactive=True)

    # 브랜드 추가 섹션
    with st.expander("새 브랜드 추가", expanded=False):
        with st.form("add_brand_form"):
            col1, col2 = st.columns(2)

            with col1:
                new_name = st.text_input("브랜드 ID (영문)", placeholder="예: naver")
                new_display_name = st.text_input("표시 이름", placeholder="예: 네이버")

            with col2:
                new_domains = st.text_area("공식 도메인 (줄바꿈 구분)", placeholder="naver.com\nnavercorp.com")
                new_keywords = st.text_area("탐지 키워드 (줄바꿈 구분)", placeholder="naver\n네이버")

            new_typos = st.text_area("오타 패턴 (줄바꿈 구분, 선택)", placeholder="naevr\nnavr")

            if st.form_submit_button("브랜드 추가", type="primary"):
                if new_name and new_display_name and new_domains:
                    try:
                        db.add_brand(
                            name=new_name.strip(),
                            display_name=new_display_name.strip(),
                            official_domains=[d.strip() for d in new_domains.strip().split("\n") if d.strip()],
                            keywords=[k.strip() for k in new_keywords.strip().split("\n") if k.strip()],
                            typos=[t.strip() for t in new_typos.strip().split("\n") if t.strip()] if new_typos else []
                        )
                        # spoofing_detector 리로드
                        from src.spoofing_detector import get_spoofing_detector
                        get_spoofing_detector().reload_brands()
                        st.success(f"'{new_display_name}' 브랜드가 추가되었습니다!")
                        st.rerun()
                    except Exception as e:
                        st.error(f"브랜드 추가 실패: {e}")
                else:
                    st.warning("필수 항목을 모두 입력해주세요.")

    st.markdown("---")

    # 브랜드 목록
    st.subheader("등록된 브랜드 목록")

    if not brands:
        st.info("등록된 브랜드가 없습니다.")
        if st.button("기본 브랜드 초기화"):
            db.init_default_brands()
            st.rerun()
    else:
        for brand in brands:
            is_active = brand.get("is_active", True)
            status_color = "#2ed573" if is_active else "#ff4757"
            status_text = "활성" if is_active else "비활성"

            with st.expander(f"[{'ON' if is_active else 'OFF'}] {brand['display_name']} ({brand['name']})"):
                col1, col2 = st.columns([3, 1])

                with col1:
                    st.markdown(f"**상태:** <span style='color:{status_color}'>{status_text}</span>", unsafe_allow_html=True)
                    st.markdown(f"**공식 도메인:** {', '.join(brand['official_domains'])}")
                    st.markdown(f"**탐지 키워드:** {', '.join(brand['keywords'])}")
                    if brand.get('typos'):
                        st.markdown(f"**오타 패턴:** {', '.join(brand['typos'])}")

                    # 레퍼런스 이미지 상태
                    ref_path = Path(__file__).parent.parent / "data" / "references" / f"{brand['name']}.png"
                    if ref_path.exists():
                        st.markdown("**레퍼런스 이미지:** 등록됨")
                        st.image(str(ref_path), width=200)
                    else:
                        st.markdown("**레퍼런스 이미지:** 미등록")

                with col2:
                    # 활성/비활성 토글
                    if is_active:
                        if st.button("비활성화", key=f"deactivate_{brand['id']}"):
                            db.update_brand(brand['id'], is_active=False)
                            from src.spoofing_detector import get_spoofing_detector
                            get_spoofing_detector().reload_brands()
                            st.rerun()
                    else:
                        if st.button("활성화", key=f"activate_{brand['id']}"):
                            db.update_brand(brand['id'], is_active=True)
                            from src.spoofing_detector import get_spoofing_detector
                            get_spoofing_detector().reload_brands()
                            st.rerun()

                    # 레퍼런스 캡처 버튼
                    if brand['official_domains']:
                        official_url = f"https://{brand['official_domains'][0]}"
                        if st.button("레퍼런스 캡처", key=f"capture_ref_{brand['id']}"):
                            _capture_reference_screenshot(brand['name'], official_url)

                # 수정 폼
                with st.form(f"edit_brand_{brand['id']}"):
                    st.markdown("**브랜드 수정**")
                    edit_display_name = st.text_input("표시 이름", value=brand['display_name'])
                    edit_domains = st.text_area("공식 도메인", value="\n".join(brand['official_domains']))
                    edit_keywords = st.text_area("탐지 키워드", value="\n".join(brand['keywords']))
                    edit_typos = st.text_area("오타 패턴", value="\n".join(brand.get('typos', [])))

                    if st.form_submit_button("수정 저장"):
                        db.update_brand(
                            brand['id'],
                            display_name=edit_display_name.strip(),
                            official_domains=[d.strip() for d in edit_domains.strip().split("\n") if d.strip()],
                            keywords=[k.strip() for k in edit_keywords.strip().split("\n") if k.strip()],
                            typos=[t.strip() for t in edit_typos.strip().split("\n") if t.strip()]
                        )
                        from src.spoofing_detector import get_spoofing_detector
                        get_spoofing_detector().reload_brands()
                        st.success("브랜드가 수정되었습니다!")
                        st.rerun()


def show_report_tab():
    """신고 리포트 탭"""
    st.subheader("경찰 신고용 리포트 생성")

    case = st.selectbox(
        "리포트 생성할 케이스",
        ["네이버 피싱 사례", "카카오 피싱 사례", "정부 사칭 사례"],
        key="report_case"
    )

    case_map = {
        "네이버 피싱 사례": "naver_phishing",
        "카카오 피싱 사례": "kakao_phishing",
        "정부 사칭 사례": "government_phishing"
    }

    data = SIMULATION_DATA[case_map[case]]

    if st.button("리포트 생성", type="primary"):
        report = f"""
# 피싱 사이트 탐지 리포트

## 기본 정보
- **탐지 일시**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
- **피싱 URL**: `{data["url"]}`
- **사칭 대상**: {data["detected_brand"]}
- **종합 위험도**: {data["risk_score"]*100:.1f}%

## WHOIS 정보
- **도메인 생성일**: {data["domain_created"]}
- **등록 기관**: {data["whois_registrar"]}

## AI 분석 결과
- **시각 유사도 (DINOv2)**: {data["visual_similarity"]*100:.1f}%
- **URL 피싱 확률 (BERT)**: {data["url_phishing_prob"]*100:.1f}%

## 판정 근거
"""
        for i, reason in enumerate(data["reason"], 1):
            report += f"{i}. {reason}\n"

        report += """
## 권고 조치
1. 해당 도메인 접속 차단 요청
2. 도메인 등록 기관에 신고
3. 피해자 발생 시 금융감독원 연계

---
*본 리포트는 안다 (An-da) AI 시스템에 의해 자동 생성되었습니다.*
"""

        st.markdown(report)

        # 다운로드 버튼
        st.download_button(
            label="리포트 다운로드 (Markdown)",
            data=report,
            file_name=f"phishing_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
            mime="text/markdown"
        )

        # JSON 다운로드
        st.download_button(
            label="데이터 다운로드 (JSON)",
            data=json.dumps(data, ensure_ascii=False, indent=2),
            file_name=f"phishing_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json"
        )


def main():
    load_custom_css()

    # 사이드바
    with st.sidebar:
        # 로고 이미지 표시
        # if LOGO_PATH.exists():
        #     st.image(str(LOGO_PATH), width=150)
        # else:
        #     st.image("https://img.icons8.com/fluency/96/000000/shield.png", width=150)
        st.title("안다 (An-da)")
        st.markdown("---")

        view_mode = st.radio(
            "화면 모드",
            ["사용자 화면", "경찰 관제 화면"],
            index=0
        )

        st.markdown("---")
        st.caption("버전: 1.0.0")
        st.caption("© 2025 안다 (An-da)")

        st.markdown("---")
        st.markdown("### 시뮬레이션 모드")
        st.info("서버 리소스 절약을 위해 미리 준비된 분석 결과를 표시합니다.")

    # 메인 화면
    if view_mode == "사용자 화면":
        show_user_view()
    else:
        show_police_view()


if __name__ == "__main__":
    main()
