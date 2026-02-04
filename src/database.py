"""
데이터베이스 모듈
SQLite 기반 분석 결과 저장 및 조회
"""

import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, asdict
from contextlib import contextmanager


# 데이터베이스 파일 경로
DB_PATH = Path("data/anda.db")


@dataclass
class AnalysisRecord:
    """분석 결과 레코드"""
    id: Optional[int] = None
    url: str = ""
    domain: str = ""
    is_phishing: bool = False
    risk_score: float = 0.0
    detected_brand: Optional[str] = None
    screenshot_path: Optional[str] = None
    created_at: Optional[str] = None


@dataclass
class PhishingDetail:
    """피싱 상세 정보 (경찰용 대시보드)"""
    id: Optional[int] = None
    analysis_id: int = 0
    impersonated_brand: str = ""  # 사칭 브랜드 명칭
    domain_created_date: Optional[str] = None  # 도메인 생성 날짜 (Whois)
    domain_registrar: Optional[str] = None  # 도메인 등록기관
    ai_reasoning: str = ""  # AI 판별 근거
    url_phishing_prob: float = 0.0
    visual_similarity: float = 0.0
    suspicious_patterns: Optional[str] = None  # JSON 문자열
    created_at: Optional[str] = None


class Database:
    """SQLite 데이터베이스 관리"""

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_tables()

    @contextmanager
    def get_connection(self):
        """데이터베이스 연결 컨텍스트 매니저"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_tables(self):
        """테이블 초기화"""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # 분석 결과 메인 테이블
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS analysis_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    is_phishing BOOLEAN NOT NULL DEFAULT 0,
                    risk_score REAL NOT NULL DEFAULT 0.0,
                    detected_brand TEXT,
                    screenshot_path TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # 피싱 상세 정보 테이블 (경찰용)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS phishing_details (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    analysis_id INTEGER NOT NULL,
                    impersonated_brand TEXT NOT NULL,
                    domain_created_date TEXT,
                    domain_registrar TEXT,
                    ai_reasoning TEXT NOT NULL,
                    url_phishing_prob REAL DEFAULT 0.0,
                    visual_similarity REAL DEFAULT 0.0,
                    suspicious_patterns TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (analysis_id) REFERENCES analysis_results(id)
                )
            """)

            # 익명 통계 테이블 (개인정보 없이 카운터만 저장)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS anonymous_statistics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    stat_date DATE NOT NULL UNIQUE,
                    total_analyses INTEGER DEFAULT 0,
                    safe_count INTEGER DEFAULT 0
                )
            """)

            # 브랜드 관리 테이블 (동적 관리)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS brands (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    display_name TEXT NOT NULL,
                    official_domains TEXT NOT NULL,
                    keywords TEXT NOT NULL,
                    typos TEXT,
                    is_active BOOLEAN DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # 통계용 인덱스
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_analysis_created
                ON analysis_results(created_at)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_analysis_phishing
                ON analysis_results(is_phishing)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_phishing_brand
                ON phishing_details(impersonated_brand)
            """)

    def increment_analysis_count(self, is_safe: bool = True):
        """
        익명 분석 카운터 증가 (개인정보 없이 통계만)
        - 전체 분석 건수와 안전 판정 건수만 저장
        - URL, 사용자 정보 등 개인정보는 저장하지 않음
        """
        today = datetime.now().strftime("%Y-%m-%d")
        with self.get_connection() as conn:
            cursor = conn.cursor()
            # UPSERT: 오늘 날짜 레코드가 있으면 업데이트, 없으면 생성
            cursor.execute("""
                INSERT INTO anonymous_statistics (stat_date, total_analyses, safe_count)
                VALUES (?, 1, ?)
                ON CONFLICT(stat_date) DO UPDATE SET
                    total_analyses = total_analyses + 1,
                    safe_count = safe_count + ?
            """, (today, 1 if is_safe else 0, 1 if is_safe else 0))

    def save_analysis(
        self,
        url: str,
        domain: str,
        is_phishing: bool,
        risk_score: float,
        detected_brand: Optional[str] = None,
        screenshot_path: Optional[str] = None
    ) -> int:
        """피싱으로 판정된 분석 결과 저장 (피싱만 저장)"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO analysis_results
                (url, domain, is_phishing, risk_score, detected_brand, screenshot_path)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (url, domain, is_phishing, risk_score, detected_brand, screenshot_path))
            return cursor.lastrowid

    def save_phishing_detail(
        self,
        analysis_id: int,
        impersonated_brand: str,
        ai_reasoning: str,
        domain_created_date: Optional[str] = None,
        domain_registrar: Optional[str] = None,
        url_phishing_prob: float = 0.0,
        visual_similarity: float = 0.0,
        suspicious_patterns: Optional[List[str]] = None
    ) -> int:
        """피싱 상세 정보 저장"""
        patterns_json = json.dumps(suspicious_patterns or [], ensure_ascii=False)

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO phishing_details
                (analysis_id, impersonated_brand, domain_created_date, domain_registrar,
                 ai_reasoning, url_phishing_prob, visual_similarity, suspicious_patterns)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                analysis_id, impersonated_brand, domain_created_date, domain_registrar,
                ai_reasoning, url_phishing_prob, visual_similarity, patterns_json
            ))
            return cursor.lastrowid

    def get_analysis_by_id(self, analysis_id: int) -> Optional[Dict[str, Any]]:
        """ID로 분석 결과 조회"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM analysis_results WHERE id = ?
            """, (analysis_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_phishing_detail(self, analysis_id: int) -> Optional[Dict[str, Any]]:
        """분석 ID로 피싱 상세 정보 조회"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM phishing_details WHERE analysis_id = ?
            """, (analysis_id,))
            row = cursor.fetchone()
            if row:
                result = dict(row)
                result["suspicious_patterns"] = json.loads(result["suspicious_patterns"] or "[]")
                return result
            return None

    def get_recent_analyses(self, limit: int = 100) -> List[Dict[str, Any]]:
        """최근 분석 결과 조회"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM analysis_results
                ORDER BY created_at DESC
                LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def get_phishing_cases(self, limit: int = 100) -> List[Dict[str, Any]]:
        """피싱으로 판정된 케이스 조회 (상세 정보 포함)"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT
                    a.id, a.url, a.domain, a.risk_score, a.detected_brand,
                    a.screenshot_path, a.created_at,
                    p.impersonated_brand, p.domain_created_date, p.domain_registrar,
                    p.ai_reasoning, p.url_phishing_prob, p.visual_similarity,
                    p.suspicious_patterns
                FROM analysis_results a
                LEFT JOIN phishing_details p ON a.id = p.analysis_id
                WHERE a.is_phishing = 1
                ORDER BY a.created_at DESC
                LIMIT ?
            """, (limit,))
            results = []
            for row in cursor.fetchall():
                record = dict(row)
                if record.get("suspicious_patterns"):
                    record["suspicious_patterns"] = json.loads(record["suspicious_patterns"])
                results.append(record)
            return results

    def get_statistics(self) -> Dict[str, Any]:
        """통계 데이터 조회 (개인정보 보호 준수)"""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # 전체 분석 수 (익명 통계 테이블에서 조회 - 개인정보 없음)
            cursor.execute("SELECT COALESCE(SUM(total_analyses), 0) FROM anonymous_statistics")
            total_count = cursor.fetchone()[0]

            # 피싱 탐지 수 (피싱만 저장된 analysis_results에서)
            cursor.execute("SELECT COUNT(*) FROM analysis_results WHERE is_phishing = 1")
            phishing_count = cursor.fetchone()[0]

            # 브랜드별 사칭 현황 (피싱 케이스만)
            cursor.execute("""
                SELECT impersonated_brand, COUNT(*) as count
                FROM phishing_details
                GROUP BY impersonated_brand
                ORDER BY count DESC
            """)
            brand_stats = [{"brand": row[0], "count": row[1]} for row in cursor.fetchall()]

            # 일별 탐지 현황 (최근 30일) - 익명 통계와 피싱 탐지 결합
            cursor.execute("""
                SELECT
                    s.stat_date as date,
                    s.total_analyses as total,
                    COALESCE(p.phishing_count, 0) as phishing
                FROM anonymous_statistics s
                LEFT JOIN (
                    SELECT DATE(created_at) as pdate, COUNT(*) as phishing_count
                    FROM analysis_results
                    WHERE is_phishing = 1 AND created_at >= DATE('now', '-30 days')
                    GROUP BY DATE(created_at)
                ) p ON s.stat_date = p.pdate
                WHERE s.stat_date >= DATE('now', '-30 days')
                ORDER BY s.stat_date
            """)
            daily_stats = [
                {"date": row[0], "total": row[1], "phishing": row[2]}
                for row in cursor.fetchall()
            ]

            # 평균 위험 점수 (피싱 케이스만)
            cursor.execute("""
                SELECT AVG(risk_score) FROM analysis_results WHERE is_phishing = 1
            """)
            avg_risk = cursor.fetchone()[0] or 0.0

            return {
                "total_analyses": total_count,
                "phishing_detected": phishing_count,
                "detection_rate": phishing_count / total_count if total_count > 0 else 0,
                "average_risk_score": round(avg_risk, 4),
                "brand_statistics": brand_stats,
                "daily_statistics": daily_stats
            }

    # ========== 브랜드 관리 메서드 ==========

    def add_brand(
        self,
        name: str,
        display_name: str,
        official_domains: List[str],
        keywords: List[str],
        typos: Optional[List[str]] = None
    ) -> int:
        """브랜드 추가"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO brands (name, display_name, official_domains, keywords, typos)
                VALUES (?, ?, ?, ?, ?)
            """, (
                name.lower(),
                display_name,
                json.dumps(official_domains, ensure_ascii=False),
                json.dumps(keywords, ensure_ascii=False),
                json.dumps(typos or [], ensure_ascii=False)
            ))
            return cursor.lastrowid

    def update_brand(
        self,
        brand_id: int,
        display_name: Optional[str] = None,
        official_domains: Optional[List[str]] = None,
        keywords: Optional[List[str]] = None,
        typos: Optional[List[str]] = None,
        is_active: Optional[bool] = None
    ) -> bool:
        """브랜드 수정"""
        updates = []
        params = []

        if display_name is not None:
            updates.append("display_name = ?")
            params.append(display_name)
        if official_domains is not None:
            updates.append("official_domains = ?")
            params.append(json.dumps(official_domains, ensure_ascii=False))
        if keywords is not None:
            updates.append("keywords = ?")
            params.append(json.dumps(keywords, ensure_ascii=False))
        if typos is not None:
            updates.append("typos = ?")
            params.append(json.dumps(typos, ensure_ascii=False))
        if is_active is not None:
            updates.append("is_active = ?")
            params.append(is_active)

        if not updates:
            return False

        updates.append("updated_at = CURRENT_TIMESTAMP")
        params.append(brand_id)

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                UPDATE brands SET {', '.join(updates)} WHERE id = ?
            """, params)
            return cursor.rowcount > 0

    def delete_brand(self, brand_id: int) -> bool:
        """브랜드 삭제 (비활성화)"""
        return self.update_brand(brand_id, is_active=False)

    def get_brand(self, brand_id: int) -> Optional[Dict[str, Any]]:
        """브랜드 단일 조회"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM brands WHERE id = ?", (brand_id,))
            row = cursor.fetchone()
            if row:
                return self._parse_brand_row(dict(row))
            return None

    def get_brand_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """브랜드명으로 조회"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM brands WHERE name = ? AND is_active = 1", (name.lower(),))
            row = cursor.fetchone()
            if row:
                return self._parse_brand_row(dict(row))
            return None

    def get_all_brands(self, include_inactive: bool = False) -> List[Dict[str, Any]]:
        """모든 브랜드 조회"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if include_inactive:
                cursor.execute("SELECT * FROM brands ORDER BY name")
            else:
                cursor.execute("SELECT * FROM brands WHERE is_active = 1 ORDER BY name")
            return [self._parse_brand_row(dict(row)) for row in cursor.fetchall()]

    def _parse_brand_row(self, row: Dict[str, Any]) -> Dict[str, Any]:
        """브랜드 행 파싱 (JSON 필드 변환)"""
        row["official_domains"] = json.loads(row["official_domains"])
        row["keywords"] = json.loads(row["keywords"])
        row["typos"] = json.loads(row["typos"]) if row["typos"] else []
        return row

    def init_default_brands(self):
        """기본 브랜드 초기화 (최초 실행 시)"""
        default_brands = [
            {
                "name": "naver",
                "display_name": "네이버",
                "official_domains": ["naver.com", "navercorp.com", "nid.naver.com"],
                "keywords": ["naver", "네이버"],
                "typos": ["naevr", "navr", "navar", "naaver", "n4ver", "nav3r"]
            },
            {
                "name": "kakao",
                "display_name": "카카오",
                "official_domains": ["kakao.com", "kakaocorp.com", "kakaobank.com", "kakaopay.com"],
                "keywords": ["kakao", "카카오"],
                "typos": ["kacao", "kaako", "kakoa", "kak4o"]
            },
            {
                "name": "google",
                "display_name": "구글",
                "official_domains": ["google.com", "google.co.kr", "gmail.com", "youtube.com"],
                "keywords": ["google", "구글", "gmail"],
                "typos": ["gogle", "googel", "g00gle", "gooogle"]
            },
            {
                "name": "government",
                "display_name": "정부기관",
                "official_domains": ["go.kr", "korea.kr", "gov.kr"],
                "keywords": ["정부", "gov", "government", "국세청", "경찰청"],
                "typos": []
            },
            {
                "name": "shinhan",
                "display_name": "신한은행",
                "official_domains": ["shinhan.com", "shinhanbank.com"],
                "keywords": ["shinhan", "신한"],
                "typos": ["sinhan", "shihan"]
            },
            {
                "name": "kookmin",
                "display_name": "국민은행",
                "official_domains": ["kbstar.com", "kookmin.com"],
                "keywords": ["kookmin", "kbstar", "국민은행", "kb"],
                "typos": ["kukmin", "kookm1n"]
            },
        ]

        for brand in default_brands:
            try:
                self.add_brand(**brand)
            except Exception:
                # 이미 존재하면 무시
                pass


# 싱글톤 인스턴스
_db_instance: Optional[Database] = None


def get_database() -> Database:
    """Database 싱글톤 인스턴스 반환"""
    global _db_instance
    if _db_instance is None:
        _db_instance = Database()
    return _db_instance
