"""Statistical feature extraction from individual images and batches for drift detection."""
from typing import Dict, List
import numpy as np


class ImageDistributionExtractor:
    """Extracts optical, radiometric, and structural statistics from images."""

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
    def extract_image_features(cls, image: np.ndarray) -> Dict[str, float]:
        """Extract radiometric, frequency, and entropy statistics from a single image."""
        arr = np.asarray(image, dtype=np.float64)
        gray = cls._to_grayscale(arr)

        # 1. Brightness: Global mean pixel intensity
        brightness = float(np.mean(arr))

        # 2. Contrast: Standard deviation of pixel intensities
        contrast = float(np.std(arr))

        # 3. Sharpness: Variance of the 2D Laplacian operator (edge high-frequency energy)
        # Using pure NumPy 4-connected discrete Laplacian stencil: [[0, 1, 0], [1, -4, 1], [0, 1, 0]]
        pad = np.pad(gray, 1, mode="edge")
        laplacian = (
            pad[2:, 1:-1]
            + pad[:-2, 1:-1]
            + pad[1:-1, 2:]
            + pad[1:-1, :-2]
            - 4.0 * pad[1:-1, 1:-1]
        )
        sharpness = float(np.var(laplacian))

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
            "brightness": brightness,
            "contrast": contrast,
            "sharpness": sharpness,
            "color_temperature": color_temperature,
            "channel_entropy": entropy,
        }

    @classmethod
    def extract_batch_distributions(cls, images: List[np.ndarray]) -> Dict[str, np.ndarray]:
        """Extract feature statistics for each image and aggregate into 1D arrays."""
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
            features = cls.extract_image_features(img)
            for k, v in features.items():
                batch_metrics[k].append(v)

        return {k: np.array(v, dtype=np.float64) for k, v in batch_metrics.items()}
