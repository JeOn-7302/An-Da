"""
스크린샷 캡처 모듈
Playwright를 사용한 웹 페이지 스크린샷 캡처
"""

import asyncio
import hashlib
from pathlib import Path
from typing import Optional
from datetime import datetime

try:
    from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeout
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


# 스크린샷 저장 경로
SCREENSHOT_DIR = Path(__file__).parent.parent / "data" / "screenshots"
SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)


class ScreenshotCapture:
    """웹 페이지 스크린샷 캡처"""

    def __init__(self, timeout: int = 30000, viewport_width: int = 1280, viewport_height: int = 720):
        """
        Args:
            timeout: 페이지 로드 타임아웃 (ms)
            viewport_width: 뷰포트 너비
            viewport_height: 뷰포트 높이
        """
        self.timeout = timeout
        self.viewport = {"width": viewport_width, "height": viewport_height}

    def _generate_filename(self, url: str) -> str:
        """URL 기반 고유 파일명 생성"""
        url_hash = hashlib.md5(url.encode()).hexdigest()[:12]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"{timestamp}_{url_hash}.png"

    async def capture_async(self, url: str, save_path: Optional[Path] = None) -> Optional[Path]:
        """
        비동기 스크린샷 캡처

        Args:
            url: 캡처할 URL
            save_path: 저장 경로 (없으면 자동 생성)

        Returns:
            저장된 스크린샷 경로 또는 None (실패 시)
        """
        if not PLAYWRIGHT_AVAILABLE:
            print("[ScreenshotCapture] Playwright가 설치되어 있지 않습니다.")
            return None

        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        if save_path is None:
            filename = self._generate_filename(url)
            save_path = SCREENSHOT_DIR / filename

        try:
            async with async_playwright() as p:
                # Chromium 브라우저 사용 (headless)
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(
                    viewport=self.viewport,
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                )
                page = await context.new_page()

                # 페이지 로드
                await page.goto(url, wait_until="networkidle", timeout=self.timeout)

                # 잠시 대기 (JavaScript 렌더링 완료)
                await asyncio.sleep(1)

                # 스크린샷 캡처
                await page.screenshot(path=str(save_path), full_page=False)

                await browser.close()

                print(f"[ScreenshotCapture] 스크린샷 저장: {save_path}")
                return save_path

        except PlaywrightTimeout:
            print(f"[ScreenshotCapture] 타임아웃: {url}")
            return None
        except Exception as e:
            print(f"[ScreenshotCapture] 캡처 실패: {e}")
            return None

    def capture(self, url: str, save_path: Optional[Path] = None) -> Optional[Path]:
        """
        동기 스크린샷 캡처 (asyncio 래퍼)

        Args:
            url: 캡처할 URL
            save_path: 저장 경로

        Returns:
            저장된 스크린샷 경로 또는 None
        """
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        return loop.run_until_complete(self.capture_async(url, save_path))

    async def capture_comparison_async(self, phishing_url: str, official_url: str) -> dict:
        """
        피싱 사이트와 공식 사이트 비교 캡처

        Args:
            phishing_url: 피싱 의심 URL
            official_url: 공식 사이트 URL

        Returns:
            {"phishing": Path, "official": Path} 또는 실패 시 None 포함
        """
        results = {"phishing": None, "official": None}

        # 병렬 캡처
        tasks = [
            self.capture_async(phishing_url),
            self.capture_async(official_url)
        ]

        captured = await asyncio.gather(*tasks, return_exceptions=True)

        if not isinstance(captured[0], Exception):
            results["phishing"] = captured[0]
        if not isinstance(captured[1], Exception):
            results["official"] = captured[1]

        return results


# 싱글톤 인스턴스
_capture_instance: Optional[ScreenshotCapture] = None


def get_screenshot_capture() -> ScreenshotCapture:
    """ScreenshotCapture 싱글톤 인스턴스"""
    global _capture_instance
    if _capture_instance is None:
        _capture_instance = ScreenshotCapture()
    return _capture_instance


# 테스트용
if __name__ == "__main__":
    capture = ScreenshotCapture()

    test_urls = [
        "https://www.naver.com",
        "https://www.google.com",
    ]

    for url in test_urls:
        result = capture.capture(url)
        if result:
            print(f"캡처 성공: {result}")
        else:
            print(f"캡처 실패: {url}")
