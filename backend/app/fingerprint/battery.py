"""Deterministic probe battery generation and standard CV perturbations."""
from typing import List, Tuple
import numpy as np
from PIL import Image, ImageFilter

from app.schemas.fingerprint import PerturbationType


class TestBatteryGenerator:
    """Generates reproducible probe datasets and controlled visual perturbations."""

    @staticmethod
    def generate_probe_images(
        seed: int = 42,
        count: int = 8,
        size: Tuple[int, int] = (64, 64),
    ) -> List[np.ndarray]:
        """Generate deterministic synthetic RGB images for the test battery."""
        rng = np.random.default_rng(seed)
        images: List[np.ndarray] = []

        for _ in range(count):
            img_arr = rng.integers(0, 256, size=(size[0], size[1], 3), dtype=np.uint8)
            images.append(img_arr)

        return images

    @staticmethod
    def apply_perturbation(image: np.ndarray, p_type: PerturbationType) -> np.ndarray:
        """Apply a specified perturbation deterministically to an input image."""
        if p_type == PerturbationType.IDENTITY:
            return image.copy()

        elif p_type == PerturbationType.GAUSSIAN_NOISE:
            # Deterministic noise seeded from image sum
            seed = int(np.sum(image, dtype=np.uint64)) % (2**31 - 1)
            rng = np.random.default_rng(seed)
            noise = rng.normal(loc=0.0, scale=20.0, size=image.shape)
            perturbed = np.clip(image.astype(np.float32) + noise, 0, 255).astype(np.uint8)
            return perturbed

        elif p_type == PerturbationType.GAUSSIAN_BLUR:
            pil_img = Image.fromarray(image)
            blurred = pil_img.filter(ImageFilter.GaussianBlur(radius=1.5))
            return np.array(blurred, dtype=np.uint8)

        elif p_type == PerturbationType.CONTRAST_SHIFT:
            # Contrast scaling (1.3x)
            scaled = np.clip(image.astype(np.float32) * 1.3, 0, 255).astype(np.uint8)
            return scaled

        elif p_type == PerturbationType.BRIGHTNESS_SHIFT:
            # Additive brightness (+30)
            shifted = np.clip(image.astype(np.float32) + 30.0, 0, 255).astype(np.uint8)
            return shifted

        elif p_type == PerturbationType.ROTATION:
            # 90-degree rotation preserving square dimensions
            return np.rot90(image, k=1).copy()

        elif p_type == PerturbationType.OCCLUSION_PATCH:
            # 16x16 zero occlusion mask in center
            occluded = image.copy()
            h, w = occluded.shape[:2]
            cy, cx = h // 2, w // 2
            half_p = min(8, h // 4, w // 4)
            occluded[cy - half_p : cy + half_p, cx - half_p : cx + half_p] = 0
            return occluded

        return image.copy()
