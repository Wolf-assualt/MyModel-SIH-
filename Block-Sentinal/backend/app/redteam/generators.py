"""Adversarial Data Attack Generators for Red-Teaming (label flipping, backdoor triggers, corruption)."""
import json
from pathlib import Path
from typing import Optional
import numpy as np
from PIL import Image

from app.core.config import settings
from app.schemas.dataset import BatchManifest, SampleRecord


class DataAttackGenerator:
    """Generates poisoned and corrupted dataset artifacts strictly isolated in quarantine."""

    def __init__(self, quarantine_dir: Optional[Path] = None):
        self.quarantine_dir = quarantine_dir or (Path(settings.DATA_DIR) / "quarantine" / "attacks")
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)

    def inject_label_flip(
        self,
        manifest: BatchManifest,
        flip_ratio: float = 0.3,
        new_label: str = "flipped",
    ) -> BatchManifest:
        """Clones a manifest and systematically mutates labels for a fraction of samples."""
        cloned_manifest = manifest.model_copy(deep=True)
        total_samples = len(cloned_manifest.samples)

        if total_samples > 0:
            num_to_flip = max(1, int(total_samples * flip_ratio))
            for i in range(num_to_flip):
                cloned_manifest.samples[i].labels = [
                    {"label": new_label, "confidence": 1.0, "source": "redteam_adversarial"}
                ]
                cloned_manifest.samples[i].metadata["redteam_flipped"] = True

        cloned_manifest.batch_id = f"{manifest.batch_id}_flipped"

        # Persist cloned tampered manifest to quarantine
        out_file = self.quarantine_dir / f"{cloned_manifest.batch_id}.json"
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(cloned_manifest.model_dump(mode="json"), f, indent=2)

        return cloned_manifest

    def inject_backdoor_trigger(
        self,
        image_path: Path,
        patch_size: int = 16,
        output_path: Optional[Path] = None,
    ) -> np.ndarray:
        """Stamps a deterministic high-contrast checkerboard pattern into bottom-right corner."""
        path = Path(image_path)
        with Image.open(path) as img:
            rgb_img = img.convert("RGB")
            w, h = rgb_img.size
            arr = np.array(rgb_img, dtype=np.uint8)

        actual_patch = min(patch_size, w, h)

        # Generate high-contrast checkerboard pattern (variance > 25.0)
        patch = np.zeros((actual_patch, actual_patch, 3), dtype=np.uint8)
        for r in range(actual_patch):
            for c in range(actual_patch):
                if ((r // 2) + (c // 2)) % 2 == 0:
                    patch[r, c] = [255, 255, 255]
                else:
                    patch[r, c] = [0, 0, 0]

        # Stamp into bottom-right corner
        arr[h - actual_patch : h, w - actual_patch : w] = patch

        out_path = output_path or (self.quarantine_dir / f"backdoor_{path.name}")
        out_img = Image.fromarray(arr)
        out_img.save(out_path)

        return arr

    def corrupt_samples(
        self,
        image_path: Path,
        output_path: Optional[Path] = None,
    ) -> np.ndarray:
        """Injects zero-variance blackout array to simulate sensor blackout or file corruption."""
        path = Path(image_path)
        with Image.open(path) as img:
            w, h = img.size

        # Create zero-variance solid array
        corrupted_arr = np.zeros((h, w, 3), dtype=np.uint8)

        out_path = output_path or (self.quarantine_dir / f"corrupt_{path.name}")
        out_img = Image.fromarray(corrupted_arr)
        out_img.save(out_path)

        return corrupted_arr
