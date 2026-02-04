"""
웹 크롤러 모듈
Playwright를 사용한 웹페이지 스크린샷 및 DOM 추출
"""

import asyncio
from dataclasses import dataclass
from typing import Optional

from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeout


@dataclass
class CrawlResult:
    """크롤링 결과 데이터 클래스"""
    url: str
    screenshot: Optional[bytes] = None
    html: Optional[str] = None
    text: Optional[str] = None
    dom_structure: Optional[str] = None
    title: Optional[str] = None
    error: Optional[str] = None
    success: bool = True


class WebCrawler:
    """웹페이지 크롤러 - 스크린샷 및 DOM 추출"""

    VIEWPORT_WIDTH = 1280
    VIEWPORT_HEIGHT = 720
    TIMEOUT_MS = 15000  # 15초 타임아웃

    def __init__(self):
        self._browser = None
        self._playwright = None

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def start(self):
        """브라우저 시작"""
        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(
            headless=True,
            args=[
                "--disable-gpu",
                "--disable-dev-shm-usage",
                "--no-sandbox",
                "--disable-setuid-sandbox",
            ]
        )

    async def close(self):
        """브라우저 종료"""
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()

    async def crawl(self, url: str) -> CrawlResult:
        """
        URL 크롤링 - 스크린샷, HTML, 텍스트, DOM 구조 추출

        Args:
            url: 크롤링할 URL

        Returns:
            CrawlResult: 크롤링 결과
        """
        if not self._browser:
            await self.start()

        result = CrawlResult(url=url)

        try:
            context = await self._browser.new_context(
                viewport={"width": self.VIEWPORT_WIDTH, "height": self.VIEWPORT_HEIGHT},
                locale="ko-KR",
                timezone_id="Asia/Seoul",
            )

            page = await context.new_page()

            # 페이지 로드
            await page.goto(url, wait_until="domcontentloaded", timeout=self.TIMEOUT_MS)

            # 동적 콘텐츠 로딩 대기 (최대 2초)
            await page.wait_for_timeout(2000)

            # 스크린샷 캡처
            result.screenshot = await page.screenshot(
                type="png",
                full_page=False,
            )

            # 페이지 제목
            result.title = await page.title()

            # HTML 전체 추출
            result.html = await page.content()

            # 텍스트 콘텐츠 추출
            result.text = await page.evaluate("() => document.body.innerText")

            # DOM 구조 추출 (간소화된 트리 구조)
            result.dom_structure = await page.evaluate("""
                () => {
                    function extractStructure(element, depth = 0) {
                        if (depth > 5) return '';  // 최대 깊이 제한

                        const tag = element.tagName?.toLowerCase();
                        if (!tag) return '';

                        // 무시할 태그
                        const ignoreTags = ['script', 'style', 'noscript', 'svg', 'path'];
                        if (ignoreTags.includes(tag)) return '';

                        const indent = '  '.repeat(depth);
                        let result = indent + '<' + tag;

                        // 주요 속성만 추출
                        const attrs = ['id', 'class', 'href', 'src', 'type', 'name', 'action'];
                        for (const attr of attrs) {
                            const value = element.getAttribute(attr);
                            if (value) {
                                const truncated = value.length > 50 ? value.slice(0, 50) + '...' : value;
                                result += ` ${attr}="${truncated}"`;
                            }
                        }
                        result += '>\\n';

                        // 자식 요소 재귀 처리
                        for (const child of element.children) {
                            result += extractStructure(child, depth + 1);
                        }

                        return result;
                    }

                    return extractStructure(document.body);
                }
            """)

            await context.close()

        except PlaywrightTimeout:
            result.success = False
            result.error = "페이지 로딩 시간 초과"
        except Exception as e:
            result.success = False
            result.error = str(e)

        return result


async def crawl_url(url: str) -> CrawlResult:
    """
    단일 URL 크롤링 헬퍼 함수

    Args:
        url: 크롤링할 URL

    Returns:
        CrawlResult: 크롤링 결과
    """
    async with WebCrawler() as crawler:
        return await crawler.crawl(url)


# 테스트용
if __name__ == "__main__":
    async def main():
        result = await crawl_url("https://www.naver.com")
        print(f"URL: {result.url}")
        print(f"Title: {result.title}")
        print(f"Success: {result.success}")
        print(f"Screenshot size: {len(result.screenshot) if result.screenshot else 0} bytes")
        print(f"HTML length: {len(result.html) if result.html else 0}")
        print(f"Text preview: {result.text[:200] if result.text else 'N/A'}...")
        print(f"\nDOM Structure preview:\n{result.dom_structure[:500] if result.dom_structure else 'N/A'}...")

    asyncio.run(main())
