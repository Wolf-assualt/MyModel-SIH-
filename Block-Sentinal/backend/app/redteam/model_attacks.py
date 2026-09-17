"""Adversarial Model and Inference Attacks for Red-Teaming."""
from pathlib import Path
from typing import Any, Dict, Optional
import uuid

from app.core.config import settings
from app.schemas.inference import InferenceDNARecord


class ModelAttackGenerator:
    """Simulates binary weight tampering and post-signature inference manipulation."""

    def __init__(self, quarantine_dir: Optional[Path] = None):
        self.quarantine_dir = quarantine_dir or (Path(settings.DATA_DIR) / "quarantine" / "models")
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)

    def tamper_model_weights(
        self,
        original_path: Path,
        output_path: Optional[Path] = None,
    ) -> Path:
        """Clones a model binary, flips bits in parameter segments, and writes to quarantine."""
        src_path = Path(original_path)
        data = bytearray(src_path.read_bytes())

        if len(data) > 0:
            # Flip byte bits in the parameter segment (middle of binary)
            mid = len(data) // 2
            for offset in range(min(32, len(data))):
                idx = (mid + offset) % len(data)
                data[idx] ^= 0xFF

        out_path = output_path or (self.quarantine_dir / f"tampered_{uuid.uuid4().hex[:12]}.bin")
        out_path.write_bytes(bytes(data))
        return out_path

    def tamper_inference_output(
        self,
        record: InferenceDNARecord,
        fake_label: str = "spoofed",
    ) -> Dict[str, Any]:
        """Alters inference predictions/digests post-signature to simulate execution spoofing."""
        tampered = record.model_dump(mode="json")
        # Invalidate the output digest while preserving original signature and DNA hash
        tampered["output_digest"] = "0" * 32 + "f" * 32
        tampered["fake_label"] = fake_label
        tampered["tamper_injected"] = True
        return tampered
