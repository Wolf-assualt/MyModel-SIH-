"""Black-box Model Adapter for models exposed solely via inference endpoints/callables."""
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
import numpy as np

from app.models_engine.adapters.base import BaseModelAdapter
from app.schemas.model import AccessMode, ModelFormat, ModelInputSpec, ModelOutputSpec


class BlackBoxAdapter(BaseModelAdapter):
    """Adapter for black-box models where graph internals and parameters are unobservable.

    Internal structural analysis is strictly marked UNAVAILABLE. Real inference and
    behavioural fingerprinting are fully supported via the provided callable.
    """

    def __init__(
        self,
        model_path: Path,
        predict_fn: Optional[Callable[[np.ndarray], np.ndarray]] = None,
    ):
        super().__init__(model_path)
        self._predict_fn = predict_fn

    @property
    def format(self) -> ModelFormat:
        return ModelFormat.BLACK_BOX

    @property
    def access_mode(self) -> AccessMode:
        return AccessMode.BLACK_BOX

    def load(self) -> None:
        """No internal binary graph loading for black-box models."""
        pass

    def metadata(self) -> Dict[str, Any]:
        """Expose explicit limitations of black-box access without fabricating internal metrics."""
        return {
            "parameter_count": 0,
            "layer_count": 0,
            "node_count": 0,
            "structural_analysis": "UNAVAILABLE",
            "access_mode": AccessMode.BLACK_BOX.value,
            "limitation": "Black-box model: Internal architecture, graph topology, and weights are unobservable.",
        }

    def input_schema(self) -> List[ModelInputSpec]:
        return [
            ModelInputSpec(name="blackbox_input", shape=[None, 3, None, None], data_type="float32")
        ]

    def output_schema(self) -> List[ModelOutputSpec]:
        return [
            ModelOutputSpec(name="blackbox_output", shape=[None, None], data_type="float32")
        ]

    def predict(self, inputs: np.ndarray) -> np.ndarray:
        """Execute real black-box forward inference."""
        if self._predict_fn is None:
            raise RuntimeError(
                "BLACKBOX_INFERENCE_UNAVAILABLE: No inference handler registered for this black-box model."
            )
        out = self._predict_fn(inputs)
        return np.array(out, dtype=np.float32)

    def fingerprint(self) -> Dict[str, Any]:
        """Internal structural fingerprint is unavailable for black-box models."""
        return {
            "graph_digest": "",
            "structural_status": "UNAVAILABLE",
            "access_mode": AccessMode.BLACK_BOX.value,
        }

    def close(self) -> None:
        pass
