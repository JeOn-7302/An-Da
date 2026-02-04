"""
시각 분석 엔진
DINOv2 기반 이미지 임베딩 및 FAISS 유사도 검색
"""

import os
from pathlib import Path
from typing import Optional, List, Tuple

import numpy as np
import torch
import faiss
from PIL import Image
from transformers import AutoImageProcessor, AutoModel


class VisionEngine:
    """DINOv2 기반 시각 분석 엔진"""

    MODEL_NAME = "facebook/dinov2-small"
    EMBEDDING_DIM = 384  # dinov2-small 임베딩 차원

    def __init__(self, targets_dir: str = "data/targets", device: str = None):
        """
        Args:
            targets_dir: 정상 사이트 이미지가 저장된 디렉토리
            device: 연산 장치 (cuda/cpu, None이면 자동 선택)
        """
        self.targets_dir = Path(targets_dir)
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")

        # 모델 로드
        self.processor = AutoImageProcessor.from_pretrained(self.MODEL_NAME)
        self.model = AutoModel.from_pretrained(self.MODEL_NAME).to(self.device)
        self.model.eval()

        # FAISS 인덱스 및 메타데이터
        self.index: Optional[faiss.IndexFlatIP] = None
        self.target_names: List[str] = []

        # 타겟 이미지 로드
        self._load_targets()

    def _load_targets(self):
        """data/targets 폴더의 정상 사이트 이미지들을 로드하고 인덱싱"""
        if not self.targets_dir.exists():
            self.targets_dir.mkdir(parents=True, exist_ok=True)
            print(f"[VisionEngine] 타겟 디렉토리 생성: {self.targets_dir}")
            return

        # 지원 이미지 확장자
        image_extensions = {".png", ".jpg", ".jpeg", ".webp"}
        image_files = [
            f for f in self.targets_dir.iterdir()
            if f.suffix.lower() in image_extensions
        ]

        if not image_files:
            print(f"[VisionEngine] 타겟 이미지가 없습니다: {self.targets_dir}")
            return

        # 임베딩 추출
        embeddings = []
        for img_path in image_files:
            try:
                embedding = self.extract_embedding(img_path)
                embeddings.append(embedding)
                self.target_names.append(img_path.stem)
            except Exception as e:
                print(f"[VisionEngine] 이미지 로드 실패 {img_path}: {e}")

        if embeddings:
            self._build_index(np.array(embeddings))
            print(f"[VisionEngine] {len(embeddings)}개 타겟 이미지 인덱싱 완료")

    def _build_index(self, embeddings: np.ndarray):
        """FAISS 인덱스 구축 (코사인 유사도용 Inner Product)"""
        # L2 정규화 (코사인 유사도를 위해)
        faiss.normalize_L2(embeddings)

        # Inner Product 인덱스 (정규화 후 IP = 코사인 유사도)
        self.index = faiss.IndexFlatIP(self.EMBEDDING_DIM)
        self.index.add(embeddings.astype(np.float32))

    def extract_embedding(self, image_input) -> np.ndarray:
        """
        이미지에서 DINOv2 임베딩 추출

        Args:
            image_input: PIL Image, 파일 경로, 또는 bytes

        Returns:
            np.ndarray: 384차원 임베딩 벡터
        """
        # 이미지 로드
        if isinstance(image_input, bytes):
            from io import BytesIO
            image = Image.open(BytesIO(image_input)).convert("RGB")
        elif isinstance(image_input, (str, Path)):
            image = Image.open(image_input).convert("RGB")
        elif isinstance(image_input, Image.Image):
            image = image_input.convert("RGB")
        else:
            raise ValueError(f"지원하지 않는 이미지 타입: {type(image_input)}")

        # 전처리 및 추론
        with torch.no_grad():
            inputs = self.processor(images=image, return_tensors="pt").to(self.device)
            outputs = self.model(**inputs)

            # CLS 토큰 임베딩 사용
            embedding = outputs.last_hidden_state[:, 0, :].cpu().numpy().flatten()

        return embedding

    def calculate_similarity(self, image_input) -> Tuple[float, str]:
        """
        입력 이미지와 타겟 이미지들의 최대 코사인 유사도 계산

        Args:
            image_input: 분석할 이미지 (PIL Image, 경로, bytes)

        Returns:
            Tuple[float, str]: (유사도 점수 0.0~1.0, 가장 유사한 타겟 이름)
        """
        if self.index is None or self.index.ntotal == 0:
            return 0.0, "no_targets"

        # 쿼리 임베딩 추출 및 정규화
        query_embedding = self.extract_embedding(image_input)
        query_embedding = query_embedding.reshape(1, -1).astype(np.float32)
        faiss.normalize_L2(query_embedding)

        # FAISS 검색 (가장 유사한 1개)
        scores, indices = self.index.search(query_embedding, k=1)

        similarity = float(scores[0][0])
        # 코사인 유사도는 -1~1 범위이므로 0~1로 정규화
        similarity = (similarity + 1) / 2
        similarity = max(0.0, min(1.0, similarity))

        matched_name = self.target_names[indices[0][0]] if indices[0][0] >= 0 else "unknown"

        return similarity, matched_name

    def search_similar(self, image_input, k: int = 5) -> List[Tuple[str, float]]:
        """
        입력 이미지와 유사한 타겟 이미지 k개 검색

        Args:
            image_input: 분석할 이미지
            k: 반환할 결과 수

        Returns:
            List[Tuple[str, float]]: [(타겟 이름, 유사도), ...]
        """
        if self.index is None or self.index.ntotal == 0:
            return []

        query_embedding = self.extract_embedding(image_input)
        query_embedding = query_embedding.reshape(1, -1).astype(np.float32)
        faiss.normalize_L2(query_embedding)

        k = min(k, self.index.ntotal)
        scores, indices = self.index.search(query_embedding, k=k)

        results = []
        for score, idx in zip(scores[0], indices[0]):
            if idx >= 0:
                similarity = (float(score) + 1) / 2
                results.append((self.target_names[idx], similarity))

        return results

    def add_target(self, image_input, name: str):
        """
        새로운 타겟 이미지 추가

        Args:
            image_input: 추가할 이미지
            name: 타겟 이름
        """
        embedding = self.extract_embedding(image_input)
        embedding = embedding.reshape(1, -1).astype(np.float32)
        faiss.normalize_L2(embedding)

        if self.index is None:
            self.index = faiss.IndexFlatIP(self.EMBEDDING_DIM)

        self.index.add(embedding)
        self.target_names.append(name)

    def get_target_count(self) -> int:
        """등록된 타겟 이미지 수 반환"""
        return len(self.target_names)


# 싱글톤 인스턴스
_engine_instance: Optional[VisionEngine] = None


def get_vision_engine(targets_dir: str = "data/targets") -> VisionEngine:
    """VisionEngine 싱글톤 인스턴스 반환"""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = VisionEngine(targets_dir=targets_dir)
    return _engine_instance


# 테스트용
if __name__ == "__main__":
    engine = VisionEngine()
    print(f"Device: {engine.device}")
    print(f"타겟 이미지 수: {engine.get_target_count()}")

    # 테스트 이미지가 있다면
    test_image = Path("data/targets")
    if test_image.exists():
        images = list(test_image.glob("*.png"))
        if images:
            similarity, matched = engine.calculate_similarity(images[0])
            print(f"테스트 유사도: {similarity:.4f}, 매칭: {matched}")
