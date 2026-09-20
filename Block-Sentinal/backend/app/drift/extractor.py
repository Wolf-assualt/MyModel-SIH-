"""Statistical feature extraction from individual images and batches for distribution shift analysis."""
from typing import Dict, List, Union
import numpy as np

from app.schemas.drift import FeatureSummary


class ImageDistributionExtractor:
    """Extracts optical, radiometric, dimensional, and structural statistics from images."""

    @staticmethod
    def _to_grayscale(image: np.ndarray) -> np.ndarray:
        """Convert an image array to 2D float64 grayscale."""
        arr = np.asarray(image, dtype=np.float64)
        if arr.ndim == 3:
            if arr.shape[2] >= 3:
                # Standard Rec. 601 luma formula
                return 0.2989 * arr[:, :, 0] + 0.5870 * arr[:, :, 1] + 0.1140 * arr[:, :, 2]
            return arr[:, :, 0]
        return arr

    @classmethod
    def compute_feature_summary(cls, values: Union[List[float], np.ndarray]) -> FeatureSummary:
        """Calculate statistical summary moments for a 1D feature array."""
        arr = np.asarray(values, dtype=np.float64).ravel()
        if len(arr) == 0:
            return FeatureSummary()
        return FeatureSummary(
            count=len(arr),
            mean=float(round(float(np.mean(arr)), 4)),
            std=float(round(float(np.std(arr)), 4)),
            min=float(round(float(np.min(arr)), 4)),
            max=float(round(float(np.max(arr)), 4)),
            median=float(round(float(np.median(arr)), 4)),
        )

    @classmethod
    def extract_image_features(cls, image: np.ndarray) -> Dict[str, float]:
        """Extract radiometric, frequency, dimensional, and entropy statistics from a single image."""
        arr = np.asarray(image, dtype=np.float64)
        gray = cls._to_grayscale(arr)

        h, w = arr.shape[:2]
        aspect_ratio = float(w / h) if h > 0 else 1.0

        # 1. Brightness: Global mean pixel intensity
        brightness = float(np.mean(arr))

        # 2. Contrast: Standard deviation of pixel intensities
        contrast = float(np.std(arr))

        # 3. Sharpness: Variance of the 2D Laplacian operator (edge high-frequency energy)
        # Using pure NumPy 4-connected discrete Laplacian stencil
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

        # 4. Color Statistics & Color Temperature
        if arr.ndim == 3 and arr.shape[2] >= 3:
            r_mean = float(np.mean(arr[:, :, 0]))
            g_mean = float(np.mean(arr[:, :, 1]))
            b_mean = float(np.mean(arr[:, :, 2]))
            r_std = float(np.std(arr[:, :, 0]))
            g_std = float(np.std(arr[:, :, 1]))
            b_std = float(np.std(arr[:, :, 2]))
            color_temperature = float(r_mean / (b_mean + 1e-6))
        else:
            r_mean = g_mean = b_mean = brightness
            r_std = g_std = b_std = contrast
            color_temperature = 1.0

        # 5. Channel Entropy: Shannon entropy of intensity histogram
        hist, _ = np.histogram(gray, bins=256, range=(0, 256))
        total_pixels = float(np.sum(hist)) + 1e-12
        probs = hist / total_pixels
        non_zero = probs[probs > 0]
        entropy = -float(np.sum(non_zero * np.log2(non_zero)))

        return {
            "brightness": brightness,
            "contrast": contrast,
            "sharpness": sharpness,
            "color_temperature": color_temperature,
            "channel_entropy": entropy,
            "dimension_width": float(w),
            "dimension_height": float(h),
            "aspect_ratio": aspect_ratio,
            "color_mean_r": r_mean,
            "color_mean_g": g_mean,
            "color_mean_b": b_mean,
            "color_std_r": r_std,
            "color_std_g": g_std,
            "color_std_b": b_std,
        }

    @classmethod
    def extract_batch_distributions(cls, images: List[np.ndarray]) -> Dict[str, np.ndarray]:
        """Extract feature statistics for each image in batch and aggregate into 1D arrays."""
        if not images:
            return {
                "brightness": np.empty(0, dtype=np.float64),
                "contrast": np.empty(0, dtype=np.float64),
                "sharpness": np.empty(0, dtype=np.float64),
                "color_temperature": np.empty(0, dtype=np.float64),
                "channel_entropy": np.empty(0, dtype=np.float64),
                "dimension_width": np.empty(0, dtype=np.float64),
                "dimension_height": np.empty(0, dtype=np.float64),
                "aspect_ratio": np.empty(0, dtype=np.float64),
                "color_mean_r": np.empty(0, dtype=np.float64),
                "color_mean_g": np.empty(0, dtype=np.float64),
                "color_mean_b": np.empty(0, dtype=np.float64),
                "color_std_r": np.empty(0, dtype=np.float64),
                "color_std_g": np.empty(0, dtype=np.float64),
                "color_std_b": np.empty(0, dtype=np.float64),
            }

        batch_metrics: Dict[str, List[float]] = {}
        for img in images:
            features = cls.extract_image_features(img)
            for k, v in features.items():
                if k not in batch_metrics:
                    batch_metrics[k] = []
                batch_metrics[k].append(v)

        return {k: np.array(v, dtype=np.float64) for k, v in batch_metrics.items()}

    extract_batch_features = extract_batch_distributions


LocalFeatureExtractor = ImageDistributionExtractor

