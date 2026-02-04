"""
WHOIS 조회 모듈
도메인 생성 날짜 및 등록기관 정보 조회
"""

import asyncio
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

import aiohttp


@dataclass
class WhoisResult:
    """WHOIS 조회 결과"""
    domain: str
    created_date: Optional[str] = None
    updated_date: Optional[str] = None
    expiry_date: Optional[str] = None
    registrar: Optional[str] = None
    registrant_country: Optional[str] = None
    name_servers: Optional[list] = None
    raw_data: Optional[str] = None
    error: Optional[str] = None
    success: bool = True


class WhoisLookup:
    """비동기 WHOIS 조회"""

    # 무료 WHOIS API 엔드포인트
    API_URL = "https://www.whoisxmlapi.com/whoisserver/WhoisService"

    def __init__(self, api_key: Optional[str] = None):
        """
        Args:
            api_key: WhoisXML API 키 (없으면 기본 파싱 사용)
        """
        self.api_key = api_key

    async def lookup(self, domain: str) -> WhoisResult:
        """
        도메인 WHOIS 정보 조회

        Args:
            domain: 조회할 도메인

        Returns:
            WhoisResult: WHOIS 조회 결과
        """
        # 도메인 정규화
        domain = self._normalize_domain(domain)
        result = WhoisResult(domain=domain)

        try:
            if self.api_key:
                return await self._lookup_api(domain)
            else:
                return await self._lookup_rdap(domain)
        except Exception as e:
            result.success = False
            result.error = str(e)
            return result

    def _normalize_domain(self, domain: str) -> str:
        """도메인 정규화 (서브도메인 제거)"""
        # www. 제거
        if domain.startswith("www."):
            domain = domain[4:]

        # 최상위 도메인과 2차 도메인만 추출
        parts = domain.split(".")
        if len(parts) > 2:
            # co.kr, go.kr 등 2단계 TLD 처리
            if parts[-2] in ["co", "go", "or", "ac", "ne", "re"]:
                return ".".join(parts[-3:])
            return ".".join(parts[-2:])
        return domain

    async def _lookup_rdap(self, domain: str) -> WhoisResult:
        """RDAP 프로토콜을 통한 WHOIS 조회 (무료)"""
        result = WhoisResult(domain=domain)

        # TLD별 RDAP 서버
        tld = domain.split(".")[-1]
        rdap_servers = {
            "com": "https://rdap.verisign.com/com/v1/domain/",
            "net": "https://rdap.verisign.com/net/v1/domain/",
            "org": "https://rdap.publicinterestregistry.org/rdap/domain/",
            "kr": "https://rdap.kisa.or.kr/rdap/domain/",
        }

        rdap_url = rdap_servers.get(tld, f"https://rdap.org/domain/")

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{rdap_url}{domain}",
                    timeout=aiohttp.ClientTimeout(total=10),
                    headers={"Accept": "application/rdap+json"}
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        result = self._parse_rdap_response(domain, data)
                    else:
                        result.success = False
                        result.error = f"RDAP 조회 실패: HTTP {response.status}"
        except asyncio.TimeoutError:
            result.success = False
            result.error = "RDAP 조회 시간 초과"
        except Exception as e:
            result.success = False
            result.error = f"RDAP 조회 오류: {str(e)}"

        return result

    def _parse_rdap_response(self, domain: str, data: dict) -> WhoisResult:
        """RDAP 응답 파싱"""
        result = WhoisResult(domain=domain)

        try:
            # 이벤트에서 날짜 정보 추출
            events = data.get("events", [])
            for event in events:
                action = event.get("eventAction", "")
                date = event.get("eventDate", "")

                if date:
                    # ISO 형식 날짜를 YYYY-MM-DD로 변환
                    try:
                        dt = datetime.fromisoformat(date.replace("Z", "+00:00"))
                        date_str = dt.strftime("%Y-%m-%d")
                    except ValueError:
                        date_str = date[:10]

                    if action == "registration":
                        result.created_date = date_str
                    elif action == "last changed" or action == "last update":
                        result.updated_date = date_str
                    elif action == "expiration":
                        result.expiry_date = date_str

            # 등록기관 정보
            entities = data.get("entities", [])
            for entity in entities:
                roles = entity.get("roles", [])
                if "registrar" in roles:
                    vcard = entity.get("vcardArray", [])
                    if len(vcard) > 1:
                        for item in vcard[1]:
                            if item[0] == "fn":
                                result.registrar = item[3]
                                break

            # 네임서버
            nameservers = data.get("nameservers", [])
            result.name_servers = [ns.get("ldhName", "") for ns in nameservers]

        except Exception as e:
            result.error = f"파싱 오류: {str(e)}"

        return result

    async def _lookup_api(self, domain: str) -> WhoisResult:
        """WhoisXML API를 통한 조회 (API 키 필요)"""
        result = WhoisResult(domain=domain)

        params = {
            "apiKey": self.api_key,
            "domainName": domain,
            "outputFormat": "JSON"
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.API_URL,
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        record = data.get("WhoisRecord", {})

                        result.created_date = record.get("createdDate", "")[:10] if record.get("createdDate") else None
                        result.updated_date = record.get("updatedDate", "")[:10] if record.get("updatedDate") else None
                        result.expiry_date = record.get("expiresDate", "")[:10] if record.get("expiresDate") else None
                        result.registrar = record.get("registrarName")

                        registrant = record.get("registrant", {})
                        result.registrant_country = registrant.get("country")
                    else:
                        result.success = False
                        result.error = f"API 조회 실패: HTTP {response.status}"
        except Exception as e:
            result.success = False
            result.error = str(e)

        return result


async def get_domain_info(domain: str) -> WhoisResult:
    """
    도메인 정보 조회 헬퍼 함수

    Args:
        domain: 조회할 도메인

    Returns:
        WhoisResult: WHOIS 조회 결과
    """
    lookup = WhoisLookup()
    return await lookup.lookup(domain)


# 테스트용
if __name__ == "__main__":
    async def main():
        result = await get_domain_info("naver.com")
        print(f"Domain: {result.domain}")
        print(f"Created: {result.created_date}")
        print(f"Registrar: {result.registrar}")
        print(f"Success: {result.success}")
        if result.error:
            print(f"Error: {result.error}")

    asyncio.run(main())
