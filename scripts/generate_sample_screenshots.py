"""
데모용 샘플 스크린샷 이미지 생성
Pillow를 사용하여 피싱/공식 사이트 목업 이미지 생성
"""

from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

# 출력 디렉토리
OUTPUT_DIR = Path(__file__).parent.parent / "data" / "examples"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# 이미지 크기 (1280x800 - 일반적인 스크린샷 비율)
WIDTH = 1280
HEIGHT = 800

# 색상 정의
COLORS = {
    "naver": {"primary": "#03C75A", "bg": "#FFFFFF", "text": "#000000"},
    "kakao": {"primary": "#FEE500", "bg": "#FFFFFF", "text": "#3C1E1E"},
    "government": {"primary": "#003366", "bg": "#F5F5F5", "text": "#333333"},
}

# 브랜드 정보
BRANDS = {
    "naver": {
        "name": "네이버",
        "phishing_url": "naver-login-security.com",
        "official_url": "nid.naver.com",
    },
    "kakao": {
        "name": "카카오",
        "phishing_url": "kakaotalk-gift.event-page.com",
        "official_url": "accounts.kakao.com",
    },
    "government": {
        "name": "정부24",
        "phishing_url": "gov-kr-tax-refund.com",
        "official_url": "www.gov.kr",
    },
}


def create_login_mockup(brand: str, is_phishing: bool) -> Image.Image:
    """로그인 페이지 목업 이미지 생성"""
    colors = COLORS.get(brand, COLORS["naver"])
    info = BRANDS.get(brand, BRANDS["naver"])

    # 기본 이미지 생성
    img = Image.new("RGB", (WIDTH, HEIGHT), colors["bg"])
    draw = ImageDraw.Draw(img)

    # 헤더 바
    header_height = 60
    draw.rectangle([0, 0, WIDTH, header_height], fill=colors["primary"])

    # URL 바 (브라우저 주소창 모방)
    url_bar_y = header_height + 10
    draw.rectangle([50, url_bar_y, WIDTH - 50, url_bar_y + 40], fill="#F0F0F0", outline="#CCCCCC")

    # URL 텍스트
    url = info["phishing_url"] if is_phishing else info["official_url"]
    protocol = "https://" if not is_phishing else "http://"

    # 폰트 (시스템 기본 폰트 사용)
    try:
        font_large = ImageFont.truetype("/System/Library/Fonts/AppleSDGothicNeo.ttc", 32)
        font_medium = ImageFont.truetype("/System/Library/Fonts/AppleSDGothicNeo.ttc", 24)
        font_small = ImageFont.truetype("/System/Library/Fonts/AppleSDGothicNeo.ttc", 18)
    except OSError:
        font_large = ImageFont.load_default()
        font_medium = ImageFont.load_default()
        font_small = ImageFont.load_default()

    # URL 표시 (피싱은 빨간색 경고)
    url_color = "#CC0000" if is_phishing else "#006600"
    draw.text((70, url_bar_y + 8), f"{protocol}{url}", fill=url_color, font=font_small)

    # 로고/브랜드명 영역
    logo_y = 200
    draw.text((WIDTH // 2 - 100, logo_y), info["name"], fill=colors["primary"], font=font_large)

    # 로그인 폼 박스
    form_x = WIDTH // 2 - 200
    form_y = 300
    form_width = 400
    form_height = 300

    draw.rectangle(
        [form_x, form_y, form_x + form_width, form_y + form_height],
        fill="#FFFFFF",
        outline="#DDDDDD",
        width=2
    )

    # 입력 필드들
    field_x = form_x + 30
    field_width = form_width - 60

    # 아이디 필드
    draw.rectangle([field_x, form_y + 40, field_x + field_width, form_y + 80], fill="#F8F8F8", outline="#CCCCCC")
    draw.text((field_x + 10, form_y + 50), "아이디", fill="#999999", font=font_small)

    # 비밀번호 필드
    draw.rectangle([field_x, form_y + 100, field_x + field_width, form_y + 140], fill="#F8F8F8", outline="#CCCCCC")
    draw.text((field_x + 10, form_y + 110), "비밀번호", fill="#999999", font=font_small)

    # 로그인 버튼
    btn_y = form_y + 170
    draw.rectangle([field_x, btn_y, field_x + field_width, btn_y + 50], fill=colors["primary"])
    draw.text((field_x + field_width // 2 - 30, btn_y + 12), "로그인", fill="#FFFFFF", font=font_medium)

    # 피싱 표시 (워터마크)
    if is_phishing:
        # 대각선 워터마크
        draw.text((WIDTH - 250, HEIGHT - 50), "[데모용 피싱 예시]", fill="#FF000033", font=font_small)
    else:
        draw.text((WIDTH - 250, HEIGHT - 50), "[데모용 공식 예시]", fill="#00660033", font=font_small)

    # 피싱 사이트 특징 추가 (미묘한 차이)
    if is_phishing:
        # 의심스러운 배너
        banner_y = HEIGHT - 100
        draw.rectangle([0, banner_y, WIDTH, banner_y + 40], fill="#FFEEEE")
        draw.text((50, banner_y + 10), "* 보안 업데이트가 필요합니다. 지금 로그인하세요!", fill="#CC0000", font=font_small)

    return img


def generate_all_samples():
    """모든 샘플 이미지 생성"""
    print(f"[생성] 샘플 이미지 저장 경로: {OUTPUT_DIR}")

    for brand in BRANDS.keys():
        # 피싱 버전
        phishing_img = create_login_mockup(brand, is_phishing=True)
        phishing_path = OUTPUT_DIR / f"{brand}_phishing.png"
        phishing_img.save(phishing_path)
        print(f"[OK] {phishing_path.name}")

        # 공식 버전
        official_img = create_login_mockup(brand, is_phishing=False)
        official_path = OUTPUT_DIR / f"{brand}_official.png"
        official_img.save(official_path)
        print(f"[OK] {official_path.name}")

    print("-" * 50)
    print(f"[완료] 총 {len(BRANDS) * 2}개 이미지 생성됨")


if __name__ == "__main__":
    generate_all_samples()
