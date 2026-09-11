"""Statistical feature extraction from individual images, tensors, and batches for drift detection."""
from pathlib import Path
from typing import Dict, List, Union
import numpy as np
from PIL import Image

from app.schemas.drift import FeatureSummary


class ImageDistributionExtractor:
    """Extracts optical, radiometric, and structural statistics from images deterministically."""

    @staticmethod
    def _to_grayscale(image: np.ndarray) -> np.ndarray:
        """Convert an image array to 2D float64 grayscale."""
        arr = np.asarray(image, dtype=np.float64)
        if arr.ndim == 3:
            if arr.shape[2] >= 3:
                # Standard Rec. 601 luma formula: 0.2989 R + 0.5870 G + 0.1140 B
                return 0.2989 * arr[:, :, 0] + 0.5870 * arr[:, :, 1] + 0.1140 * arr[:, :, 2]
            return arr[:, :, 0]
        return arr

    @classmethod
    def extract_image_features(cls, image: Union[np.ndarray, Image.Image, Path, str]) -> Dict[str, float]:
        """Extract radiometric, frequency, and entropy statistics from a single image."""
        if isinstance(image, (str, Path)):
            pil_img = Image.open(image).convert("RGB")
            arr = np.asarray(pil_img, dtype=np.float64)
        elif isinstance(image, Image.Image):
            arr = np.asarray(image.convert("RGB"), dtype=np.float64)
        else:
            arr = np.asarray(image, dtype=np.float64)

        if arr.size == 0:
            return {
                "brightness": 0.0,
                "contrast": 0.0,
                "sharpness": 0.0,
                "color_temperature": 1.0,
                "channel_entropy": 0.0,
            }

        gray = cls._to_grayscale(arr)

        # 1. Brightness: Global mean pixel intensity [0.0, 255.0]
        brightness = float(np.mean(arr))

        # 2. Contrast: Standard deviation of pixel intensities
        contrast = float(np.std(arr))

        # 3. Sharpness: Variance of the 2D Laplacian operator (high-frequency spatial energy)
        # Discrete 4-connected Laplacian stencil
        if gray.shape[0] >= 3 and gray.shape[1] >= 3:
            pad = np.pad(gray, 1, mode="edge")
            laplacian = (
                pad[2:, 1:-1]
                + pad[:-2, 1:-1]
                + pad[1:-1, 2:]
                + pad[1:-1, :-2]
                - 4.0 * pad[1:-1, 1:-1]
            )
            sharpness = float(np.var(laplacian))
        else:
            sharpness = 0.0

        # 4. Color Temperature: Ratio of Red mean to Blue mean
        if arr.ndim == 3 and arr.shape[2] >= 3:
            r_mean = float(np.mean(arr[:, :, 0]))
            b_mean = float(np.mean(arr[:, :, 2]))
            color_temperature = float(r_mean / (b_mean + 1e-6))
        else:
            color_temperature = 1.0

        # 5. Channel Entropy: Shannon entropy of the intensity distribution
        hist, _ = np.histogram(gray, bins=256, range=(0, 256))
        total_pixels = float(np.sum(hist)) + 1e-12
        probs = hist / total_pixels
        non_zero = probs[probs > 0]
        entropy = -float(np.sum(non_zero * np.log2(non_zero)))

        return {
            "brightness": float(round(brightness, 4)),
            "contrast": float(round(contrast, 4)),
            "sharpness": float(round(sharpness, 4)),
            "color_temperature": float(round(color_temperature, 4)),
            "channel_entropy": float(round(entropy, 4)),
        }

    @classmethod
    def extract_batch_distributions(
        cls, images: List[Union[np.ndarray, Image.Image, Path, str]]
    ) -> Dict[str, np.ndarray]:
        """Extract feature statistics for a list of images and aggregate into 1D NumPy arrays."""
        if not images:
            return {
                "brightness": np.empty(0, dtype=np.float64),
                "contrast": np.empty(0, dtype=np.float64),
                "sharpness": np.empty(0, dtype=np.float64),
                "color_temperature": np.empty(0, dtype=np.float64),
                "channel_entropy": np.empty(0, dtype=np.float64),
            }

        batch_metrics: Dict[str, List[float]] = {
            "brightness": [],
            "contrast": [],
            "sharpness": [],
            "color_temperature": [],
            "channel_entropy": [],
        }

        for img in images:
            feats = cls.extract_image_features(img)
            for k, v in feats.items():
                batch_metrics[k].append(v)

        return {k: np.array(v, dtype=np.float64) for k, v in batch_metrics.items()}

    @staticmethod
    def compute_feature_summary(values: Union[List[float], np.ndarray]) -> FeatureSummary:
        """Calculate summary statistics for a feature vector."""
        arr = np.asarray(values, dtype=np.float64).ravel()
        if len(arr) == 0:
            return FeatureSummary()

        return FeatureSummary(
            count=len(arr),
            mean=float(round(np.mean(arr), 4)),
            std=float(round(np.std(arr), 4)),
            min=float(round(np.min(arr), 4)),
            max=float(round(np.max(arr), 4)),
            median=float(round(np.median(arr), 4)),
            p25=float(round(np.percentile(arr, 25), 4)),
            p75=float(round(np.percentile(arr, 75), 4)),
        )
