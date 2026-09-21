"""Safe Generic Binary Model Adapter for unparsed model weights or proprietary binaries."""
from pathlib import Path
from typing import Any, Dict, List
import numpy as np

from app.crypto.canonical import canonical_json_hash
from app.models_engine.adapters.base import BaseModelAdapter
from app.schemas.model import AccessMode, ModelFormat, ModelInputSpec, ModelOutputSpec


class GenericBinaryAdapter(BaseModelAdapter):
    """Adapter for raw generic binary model files.

    Performs safe static binary inspection without code execution.
    Internal graph parsing is marked unavailable, while exact binary SHA-256 and byte statistics
    provide authoritative integrity verification.
    """

    def __init__(self, model_path: Path):
        super().__init__(model_path)
        self._file_size = self.model_path.stat().st_size

    @property
    def format(self) -> ModelFormat:
        return ModelFormat.GENERIC_BINARY

    @property
    def access_mode(self) -> AccessMode:
        return AccessMode.PARTIAL

    def load(self) -> None:
        """Validate binary readability without executing code."""
        if not self.model_path.is_file():
            raise FileNotFoundError(f"Binary file not found: {self.model_path}")
        self._file_size = self.model_path.stat().st_size

    def metadata(self) -> Dict[str, Any]:
        """Extract deterministic file-level binary metadata."""
        return {
            "parameter_count": self._file_size // 4,
            "node_count": 1,
            "layer_count": 1,
            "file_size_bytes": self._file_size,
            "framework": "generic_binary",
            "access_mode": AccessMode.PARTIAL.value,
        }

    def input_schema(self) -> List[ModelInputSpec]:
        return [ModelInputSpec(name="binary_input", shape=[None], data_type="bytes")]

    def output_schema(self) -> List[ModelOutputSpec]:
        return [ModelOutputSpec(name="binary_output", shape=[None], data_type="bytes")]

    def predict(self, inputs: np.ndarray) -> np.ndarray:
        """Forward execution is unavailable for raw binary without a dedicated runtime."""
        raise RuntimeError(
            "GENERIC_BINARY_RUNTIME_UNAVAILABLE: Raw binary files cannot be executed without a runtime interpreter."
        )

    def fingerprint(self) -> Dict[str, Any]:
        """Compute deterministic canonical digest of the binary payload."""
        digest = canonical_json_hash({
            "sha256": self.artifact_hash,
            "size": self._file_size,
        })
        return {
            "graph_digest": digest,
            "binary_sha256": self.artifact_hash,
            "weight_tensors_count": 1,
        }

    def close(self) -> None:
        pass
