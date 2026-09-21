"""Safe PyTorch Model Adapter using weights_only inspection.

Arbitrary Python-dependent execution is rejected as PYTORCH_RUNTIME_UNAVAILABLE.
"""
from pathlib import Path
from typing import Any, Dict, List, Optional
# pyrefly: ignore [missing-import]
import numpy as np

# pyrefly: ignore [missing-import]
import torch

from app.crypto.canonical import canonical_json_hash, hash_bytes
from app.models_engine.adapters.base import BaseModelAdapter
from app.schemas.model import AccessMode, ModelFormat, ModelInputSpec, ModelOutputSpec


class PyTorchAdapter(BaseModelAdapter):
    """Safe PyTorch weights adapter.

    Restricted strictly to weights_only=True. Does not execute arbitrary pickled code.
    Forward inference raises PYTORCH_RUNTIME_UNAVAILABLE because raw weights do not include
    an executable computational graph.
    """

    def __init__(self, model_path: Path):
        super().__init__(model_path)
        self._state_dict: Optional[Dict[str, torch.Tensor]] = None
        self._tensors_meta: Dict[str, Any] = {}

    @property
    def format(self) -> ModelFormat:
        return ModelFormat.PYTORCH_WEIGHTS

    @property
    def access_mode(self) -> AccessMode:
        return AccessMode.PARTIAL

    def load(self) -> None:
        """Safely load state_dict using weights_only=True."""
        if self._state_dict is not None:
            return

        try:
            # Safe loading: weights_only=True strictly disallows arbitrary unpickling
            data = torch.load(str(self.model_path), map_location="cpu", weights_only=True)
        except Exception as exc:
            raise ValueError(
                f"PYTORCH_RUNTIME_UNAVAILABLE: Unsafe pickle or unsupported format in {self.model_path.name}: {exc}"
            )

        if isinstance(data, dict):
            if "state_dict" in data and isinstance(data["state_dict"], dict):
                self._state_dict = data["state_dict"]
            elif "model" in data and isinstance(data["model"], dict):
                self._state_dict = data["model"]
            else:
                self._state_dict = data
        else:
            raise ValueError("PYTORCH_RUNTIME_UNAVAILABLE: Checkpoint is not a dictionary state_dict.")

    def metadata(self) -> Dict[str, Any]:
        """Extract exact parameter counts and layer names from safe state_dict."""
        if self._state_dict is None:
            self.load()

        assert self._state_dict is not None

        param_count = 0
        layer_names = []
        shapes = {}
        for k, v in self._state_dict.items():
            if hasattr(v, "numel"):
                param_count += v.numel()
                layer_names.append(k)
                shapes[k] = list(v.shape)

        return {
            "parameter_count": param_count,
            "layer_count": len(layer_names),
            "node_count": len(layer_names),
            "tensor_names": layer_names[:100],
            "framework": "pytorch_weights_only",
            "runtime_available": False,
            "inference_limitation": "PYTORCH_RUNTIME_UNAVAILABLE",
        }

    def input_schema(self) -> List[ModelInputSpec]:
        if self._state_dict is None:
            self.load()
        # Find first weight tensor dimension if present
        first_tensor = next(iter(self._state_dict.values())) if self._state_dict else None
        in_shape = list(first_tensor.shape) if first_tensor is not None else [None]
        return [ModelInputSpec(name="state_dict_input", shape=in_shape, data_type="float32")]

    def output_schema(self) -> List[ModelOutputSpec]:
        if self._state_dict is None:
            self.load()
        last_tensor = list(self._state_dict.values())[-1] if self._state_dict else None
        out_shape = list(last_tensor.shape) if last_tensor is not None else [None]
        return [ModelOutputSpec(name="state_dict_output", shape=out_shape, data_type="float32")]

    def predict(self, inputs: np.ndarray) -> np.ndarray:
        """Report runtime unavailable: raw state_dict lacks executable computational graph.

        Security contract: arbitrary Python-dependent execution is forbidden.
        Use _synthetic_forward() for deterministic weight-sensitive fingerprinting.
        """
        raise RuntimeError(
            "PYTORCH_RUNTIME_UNAVAILABLE: Execution of raw PyTorch state_dict requires external model "
            "class definition. Arbitrary Python-dependent execution is forbidden for security."
        )

    def _synthetic_forward(self, inputs: np.ndarray) -> np.ndarray:
        """Deterministic weight-sensitive forward pass for behavioural fingerprinting only.

        NOT arbitrary code execution — applies loaded weight tensors through a fixed
        linear projection to produce a content-sensitive (N, 10) softmax output.
        Called by ModelExecutor when PYTORCH_RUNTIME_UNAVAILABLE is raised.
        """
        if self._state_dict is None:
            self.load()

        assert self._state_dict is not None

        weight_tensors = [
            v.detach().cpu().numpy().flatten()
            for k, v in self._state_dict.items()
            if "weight" in k and v.ndim >= 1
        ]
        bias_tensors = [
            v.detach().cpu().numpy().flatten()
            for k, v in self._state_dict.items()
            if "bias" in k and v.ndim == 1
        ]

        if not weight_tensors:
            n = inputs.shape[0] if inputs.ndim > 1 else 1
            return np.full((n, 10), 0.1, dtype=np.float32)

        param_vec = np.concatenate(weight_tensors).astype(np.float64)
        bias_vec = np.concatenate(bias_tensors).astype(np.float64) if bias_tensors else np.zeros(1)

        if inputs.ndim == 4:
            x = inputs.reshape(inputs.shape[0], -1).astype(np.float64) / 255.0
        elif inputs.ndim == 3:
            x = inputs.reshape(1, -1).astype(np.float64) / 255.0
        else:
            x = inputs.astype(np.float64)

        flat_dim = x.shape[1]
        rng = np.random.default_rng(int(abs(param_vec[:8].sum()) * 1e6) % (2**31 - 1))
        proj_dim = min(flat_dim, len(param_vec))
        W = (
            param_vec[:proj_dim * 10].reshape(-1, 10)
            if len(param_vec) >= proj_dim * 10
            else rng.normal(0, 1, (proj_dim, 10)) * (np.std(param_vec) + 1e-8)
        )
        b = bias_vec[:10] if len(bias_vec) >= 10 else np.pad(bias_vec, (0, 10 - len(bias_vec)))

        logits = x[:, :proj_dim] @ W + b
        logits -= logits.max(axis=1, keepdims=True)
        exp_l = np.exp(logits)
        return (exp_l / exp_l.sum(axis=1, keepdims=True)).astype(np.float32)


    def fingerprint(self) -> Dict[str, Any]:
        """Compute deterministic canonical digest of all weights."""
        if self._state_dict is None:
            self.load()

        assert self._state_dict is not None

        tensor_entries = []
        for name in sorted(self._state_dict.keys()):
            tensor = self._state_dict[name]
            if hasattr(tensor, "detach"):
                t_bytes = tensor.detach().cpu().numpy().tobytes()
                tensor_entries.append({
                    "name": name,
                    "shape": list(tensor.shape),
                    "sha256": hash_bytes(t_bytes),
                })

        digest = canonical_json_hash({"weights": tensor_entries})
        return {
            "graph_digest": digest,
            "weight_tensors_count": len(tensor_entries),
        }

    def close(self) -> None:
        self._state_dict = None
