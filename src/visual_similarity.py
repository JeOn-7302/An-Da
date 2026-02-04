"""
시각 유사도 분석 모듈
pHash (Perceptual Hash) + SSIM (Structural Similarity Index) 기반 이미지 비교
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple, Union
import hashlib

try:
    from PIL import Image
    import numpy as np
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    from skimage.metrics import structural_similarity as ssim
    from skimage import color
    SKIMAGE_AVAILABLE = True
except ImportError:
    SKIMAGE_AVAILABLE = False


@dataclass
class SimilarityResult:
    """유사도 분석 결과"""
    phash_similarity: float  # pHash 유사도 (0.0 ~ 1.0)
    ssim_similarity: float   # SSIM 유사도 (0.0 ~ 1.0)
    combined_similarity: float  # 종합 유사도
    is_similar: bool  # 유사 여부 (90% 이상이면 True)
    phash_distance: int  # 해밍 거리 (낮을수록 유사)
    details: dict


class VisualSimilarityAnalyzer:
    """pHash + SSIM 기반 시각 유사도 분석"""

    # pHash 크기 (8x8 = 64bit hash)
    HASH_SIZE = 8

    # 유사도 임계값
    SIMILARITY_THRESHOLD = 0.85  # 85% 이상이면 유사

    def __init__(self, hash_size: int = 8, threshold: float = 0.85):
        """
        Args:
            hash_size: pHash 크기 (기본 8x8)
            threshold: 유사도 임계값 (기본 0.85)
        """
        self.hash_size = hash_size
        self.threshold = threshold

    def _load_image(self, image_source: Union[str, Path, Image.Image]) -> Optional[Image.Image]:
        """이미지 로드"""
        if not PIL_AVAILABLE:
            print("[VisualSimilarity] Pillow가 설치되어 있지 않습니다.")
            return None

        if isinstance(image_source, Image.Image):
            return image_source

        try:
            return Image.open(image_source)
        except Exception as e:
            print(f"[VisualSimilarity] 이미지 로드 실패: {e}")
            return None

    def compute_phash(self, image: Union[str, Path, Image.Image]) -> Optional[str]:
        """
        Perceptual Hash (pHash) 계산

        1. 이미지를 작은 크기로 리사이즈 (hash_size+1 x hash_size)
        2. 그레이스케일 변환
        3. DCT (Discrete Cosine Transform) 적용
        4. 중앙값 기준 이진화

        Args:
            image: 이미지 경로 또는 PIL Image

        Returns:
            16진수 해시 문자열 또는 None
        """
        if not PIL_AVAILABLE:
            return None

        img = self._load_image(image)
        if img is None:
            return None

        # 그레이스케일 변환
        img = img.convert("L")

        # 리사이즈 (hash_size+1 x hash_size로 - 차분 계산용)
        img = img.resize((self.hash_size + 1, self.hash_size), Image.Resampling.LANCZOS)

        # numpy 배열로 변환
        pixels = np.array(img, dtype=np.float64)

        # 차분 계산 (좌우 픽셀 비교)
        diff = pixels[:, 1:] > pixels[:, :-1]

        # 해시 비트열 생성
        hash_bits = diff.flatten()

        # 16진수 문자열로 변환
        hash_int = sum(bit << i for i, bit in enumerate(hash_bits))
        hash_hex = format(hash_int, f"0{self.hash_size * self.hash_size // 4}x")

        return hash_hex

    def hamming_distance(self, hash1: str, hash2: str) -> int:
        """
        두 해시 간 해밍 거리 계산

        Args:
            hash1: 첫 번째 pHash
            hash2: 두 번째 pHash

        Returns:
            해밍 거리 (다른 비트 수)
        """
        if len(hash1) != len(hash2):
            return -1

        # 16진수를 정수로 변환
        int1 = int(hash1, 16)
        int2 = int(hash2, 16)

        # XOR 후 1인 비트 수 계산
        xor_result = int1 ^ int2
        return bin(xor_result).count("1")

    def phash_similarity(self, hash1: str, hash2: str) -> float:
        """
        pHash 유사도 계산 (0.0 ~ 1.0)

        Args:
            hash1: 첫 번째 pHash
            hash2: 두 번째 pHash

        Returns:
            유사도 (1.0에 가까울수록 유사)
        """
        distance = self.hamming_distance(hash1, hash2)
        if distance < 0:
            return 0.0

        max_distance = self.hash_size * self.hash_size
        similarity = 1.0 - (distance / max_distance)
        return similarity

    def compute_ssim(
        self,
        image1: Union[str, Path, Image.Image],
        image2: Union[str, Path, Image.Image],
        resize_to: Tuple[int, int] = (256, 256)
    ) -> float:
        """
        SSIM (Structural Similarity Index) 계산

        Args:
            image1: 첫 번째 이미지
            image2: 두 번째 이미지
            resize_to: 비교를 위한 리사이즈 크기

        Returns:
            SSIM 값 (0.0 ~ 1.0, 1에 가까울수록 유사)
        """
        if not PIL_AVAILABLE or not SKIMAGE_AVAILABLE:
            print("[VisualSimilarity] Pillow 또는 scikit-image가 설치되어 있지 않습니다.")
            return 0.0

        img1 = self._load_image(image1)
        img2 = self._load_image(image2)

        if img1 is None or img2 is None:
            return 0.0

        # 동일 크기로 리사이즈
        img1 = img1.resize(resize_to, Image.Resampling.LANCZOS)
        img2 = img2.resize(resize_to, Image.Resampling.LANCZOS)

        # 그레이스케일 변환
        img1 = img1.convert("L")
        img2 = img2.convert("L")

        # numpy 배열로 변환
        arr1 = np.array(img1)
        arr2 = np.array(img2)

        # SSIM 계산
        try:
            similarity, _ = ssim(arr1, arr2, full=True)
            return max(0.0, min(1.0, similarity))  # 0~1 범위로 클램핑
        except Exception as e:
            print(f"[VisualSimilarity] SSIM 계산 실패: {e}")
            return 0.0

    def analyze(
        self,
        image1: Union[str, Path, Image.Image],
        image2: Union[str, Path, Image.Image]
    ) -> SimilarityResult:
        """
        두 이미지의 시각 유사도 종합 분석

        Args:
            image1: 첫 번째 이미지 (피싱 의심)
            image2: 두 번째 이미지 (공식 사이트)

        Returns:
            SimilarityResult: 종합 분석 결과
        """
        # pHash 계산
        hash1 = self.compute_phash(image1)
        hash2 = self.compute_phash(image2)

        if hash1 and hash2:
            phash_sim = self.phash_similarity(hash1, hash2)
            hamming_dist = self.hamming_distance(hash1, hash2)
        else:
            phash_sim = 0.0
            hamming_dist = -1

        # SSIM 계산
        ssim_sim = self.compute_ssim(image1, image2)

        # 종합 유사도 (pHash 40% + SSIM 60%)
        # SSIM이 구조적 유사성을 더 잘 반영하므로 가중치 높게
        combined = phash_sim * 0.4 + ssim_sim * 0.6

        # 유사 여부 판정
        is_similar = combined >= self.threshold

        return SimilarityResult(
            phash_similarity=phash_sim,
            ssim_similarity=ssim_sim,
            combined_similarity=combined,
            is_similar=is_similar,
            phash_distance=hamming_dist,
            details={
                "phash1": hash1,
                "phash2": hash2,
                "threshold": self.threshold,
                "method": "pHash(40%) + SSIM(60%)"
            }
        )


# 브랜드별 공식 사이트 레퍼런스 이미지 경로
REFERENCE_DIR = Path(__file__).parent.parent / "data" / "references"
REFERENCE_DIR.mkdir(parents=True, exist_ok=True)


class BrandReferenceManager:
    """브랜드별 공식 사이트 레퍼런스 이미지 관리"""

    def __init__(self):
        self.reference_dir = REFERENCE_DIR

    def get_reference_path(self, brand_name: str) -> Optional[Path]:
        """브랜드의 레퍼런스 이미지 경로 반환"""
        ref_path = self.reference_dir / f"{brand_name.lower()}.png"
        return ref_path if ref_path.exists() else None

    def save_reference(self, brand_name: str, image: Union[str, Path, Image.Image]) -> Path:
        """브랜드 레퍼런스 이미지 저장"""
        if not PIL_AVAILABLE:
            raise RuntimeError("Pillow가 설치되어 있지 않습니다.")

        ref_path = self.reference_dir / f"{brand_name.lower()}.png"

        if isinstance(image, (str, Path)):
            img = Image.open(image)
        else:
            img = image

        img.save(ref_path, "PNG")
        return ref_path

    def list_references(self) -> list:
        """저장된 모든 레퍼런스 목록"""
        return [p.stem for p in self.reference_dir.glob("*.png")]


# 싱글톤 인스턴스
_analyzer_instance: Optional[VisualSimilarityAnalyzer] = None
_reference_manager: Optional[BrandReferenceManager] = None


def get_visual_analyzer() -> VisualSimilarityAnalyzer:
    """VisualSimilarityAnalyzer 싱글톤"""
    global _analyzer_instance
    if _analyzer_instance is None:
        _analyzer_instance = VisualSimilarityAnalyzer()
    return _analyzer_instance


def get_reference_manager() -> BrandReferenceManager:
    """BrandReferenceManager 싱글톤"""
    global _reference_manager
    if _reference_manager is None:
        _reference_manager = BrandReferenceManager()
    return _reference_manager


# 테스트용
if __name__ == "__main__":
    analyzer = VisualSimilarityAnalyzer()

    # 테스트 이미지가 있다면 비교
    test_dir = Path(__file__).parent.parent / "data" / "screenshots"
    images = list(test_dir.glob("*.png"))

    if len(images) >= 2:
        result = analyzer.analyze(images[0], images[1])
        print(f"pHash 유사도: {result.phash_similarity:.2%}")
        print(f"SSIM 유사도: {result.ssim_similarity:.2%}")
        print(f"종합 유사도: {result.combined_similarity:.2%}")
        print(f"유사 판정: {result.is_similar}")
        print(f"해밍 거리: {result.phash_distance}")
    else:
        print("비교할 이미지가 부족합니다.")
