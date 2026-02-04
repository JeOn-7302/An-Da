"""
레퍼런스 이미지 자동 생성 스크립트
정상 사이트들의 스크린샷을 data/references에 저장
(브랜드별 시각 유사도 비교용)
"""

import asyncio
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.screenshot_capture import ScreenshotCapture
from src.visual_similarity import get_reference_manager

# 정상 사이트 목록 (브랜드별 공식 사이트)
TARGET_SITES = {
    "naver": "https://nid.naver.com/nidlogin.login",
    "kakao": "https://accounts.kakao.com/login",
    "google": "https://accounts.google.com",
    "government": "https://www.gov.kr",
    "kookmin": "https://www.kbstar.com",
    "shinhan": "https://www.shinhan.com",
}


async def setup_references():
    """레퍼런스 이미지 생성"""
    ref_manager = get_reference_manager()
    capture = ScreenshotCapture()

    print(f"[Setup] 레퍼런스 이미지 저장 경로: {ref_manager.reference_dir}")
    print(f"[Setup] 생성할 레퍼런스 수: {len(TARGET_SITES)}")
    print("-" * 50)

    for brand, url in TARGET_SITES.items():
        ref_path = ref_manager.get_reference_path(brand)

        # 이미 존재하면 스킵
        if ref_path and ref_path.exists():
            print(f"[Skip] {brand}: 이미 존재함")
            continue

        print(f"[Capture] {brand}: {url}")

        try:
            result = await capture.capture_async(url)

            if result:
                # 레퍼런스로 저장
                saved_path = ref_manager.save_reference(brand, result)
                print(f"[OK] {brand}: {saved_path}")
            else:
                print(f"[FAIL] {brand}: 캡처 실패")

        except Exception as e:
            print(f"[ERROR] {brand}: {e}")

    print("-" * 50)
    print(f"[Setup] 완료! 등록된 레퍼런스: {ref_manager.list_references()}")


if __name__ == "__main__":
    asyncio.run(setup_references())
