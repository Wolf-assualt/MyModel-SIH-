"""Common Model Adapter interface for TRUST-CV model assurance."""
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional
import numpy as np

from app.crypto.canonical import hash_file
from app.schemas.model import AccessMode, ModelFormat, ModelInputSpec, ModelOutputSpec


class BaseModelAdapter(ABC):
    """Abstract base model adapter providing common interface across CV model formats."""

    def __init__(self, model_path: Path):
        self.model_path = Path(model_path)
        if not self.model_path.is_file():
            raise FileNotFoundError(f"Model file not found: {self.model_path}")
        # Always calculate SHA-256 directly from the current model artifact on disk
        self._artifact_hash = hash_file(str(self.model_path))

    @property
    def artifact_hash(self) -> str:
        """SHA-256 digest computed directly from the current model artifact on disk."""
        return self._artifact_hash

    def rehash(self) -> str:
        """Re-read and verify current artifact hash from disk."""
        self._artifact_hash = hash_file(str(self.model_path))
        return self._artifact_hash

    @property
    @abstractmethod
    def format(self) -> ModelFormat:
        """Format of the model."""
        pass

    @property
    @abstractmethod
    def access_mode(self) -> AccessMode:
        """Access mode: WHITE_BOX, BLACK_BOX, or PARTIAL."""
        pass

    @abstractmethod
    def load(self) -> None:
        """Load model binary into runtime session."""
        pass

    @abstractmethod
    def metadata(self) -> Dict[str, Any]:
        """Extract architectural information, parameter statistics, and node information."""
        pass

    @abstractmethod
    def input_schema(self) -> List[ModelInputSpec]:
        """Return list of model input specifications."""
        pass

    @abstractmethod
    def output_schema(self) -> List[ModelOutputSpec]:
        """Return list of model output specifications."""
        pass

    @abstractmethod
    def predict(self, inputs: np.ndarray) -> np.ndarray:
        """Perform real forward inference on provided input batch.

        Args:
            inputs: Numpy ndarray of shape (batch, channels, height, width) or (batch, height, width, channels)
                    or flattened features.

        Returns:
            Numpy ndarray containing model output logits or probabilities.
        """
        pass

    @abstractmethod
    def fingerprint(self) -> Dict[str, Any]:
        """Extract structural/internal parameter fingerprint."""
        pass

    @abstractmethod
    def close(self) -> None:
        """Release allocated runtime sessions, memory, and file handles."""
        pass

    def __enter__(self):
        self.load()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
