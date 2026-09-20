"""TorchScript Model Adapter supporting safe JIT loading and real inference."""
from pathlib import Path
from typing import Any, Dict, List, Optional
import numpy as np
from PIL import Image

import torch

from app.crypto.canonical import canonical_json_hash, hash_bytes
from app.models_engine.adapters.base import BaseModelAdapter
from app.schemas.model import AccessMode, ModelFormat, ModelInputSpec, ModelOutputSpec


class TorchScriptAdapter(BaseModelAdapter):
    """Safe local loading and real inference execution for TorchScript models."""

    def __init__(self, model_path: Path):
        super().__init__(model_path)
        self._model: Optional[torch.jit.ScriptModule] = None
        self._inputs_meta: List[ModelInputSpec] = []
        self._outputs_meta: List[ModelOutputSpec] = []

    @property
    def format(self) -> ModelFormat:
        return ModelFormat.TORCHSCRIPT

    @property
    def access_mode(self) -> AccessMode:
        return AccessMode.WHITE_BOX

    def load(self) -> None:
        """Safely load TorchScript JIT model."""
        if self._model is not None:
            return

        # Safe JIT load on CPU
        self._model = torch.jit.load(str(self.model_path), map_location="cpu")
        self._model.eval()

        # Introspect forward signature if available
        self._inputs_meta = []
        self._outputs_meta = []

        try:
            schema = self._model.forward.schema
            for arg in schema.arguments:
                if arg.name != "self":
                    self._inputs_meta.append(
                        ModelInputSpec(
                            name=arg.name,
                            shape=[None, 3, None, None],
                            data_type=str(arg.type),
                        )
                    )
            for ret in schema.returns:
                self._outputs_meta.append(
                    ModelOutputSpec(
                        name="output",
                        shape=[None, None],
                        data_type=str(ret.type),
                    )
                )
        except Exception:
            # If schema not cleanly introspectable, provide non-fabricated schema
            self._inputs_meta = [ModelInputSpec(name="input", shape=[None, 3, None, None], data_type="Tensor")]
            self._outputs_meta = [ModelOutputSpec(name="output", shape=[None, None], data_type="Tensor")]

    def metadata(self) -> Dict[str, Any]:
        """Extract TorchScript parameter counts, submodules, and buffer statistics."""
        if self._model is None:
            self.load()

        assert self._model is not None

        param_count = sum(p.numel() for p in self._model.parameters())
        buffer_count = sum(b.numel() for b in self._model.buffers())
        named_modules = [name for name, _ in self._model.named_modules() if name]

        return {
            "parameter_count": param_count,
            "buffer_count": buffer_count,
            "layer_count": max(1, len(named_modules)),
            "node_count": max(1, len(named_modules)),
            "submodules": named_modules[:50],
            "framework": "torchscript",
            "torch_version": torch.__version__,
        }

    def input_schema(self) -> List[ModelInputSpec]:
        if not self._inputs_meta:
            self.load()
        return self._inputs_meta

    def output_schema(self) -> List[ModelOutputSpec]:
        if not self._outputs_meta:
            self.load()
        return self._outputs_meta

    def _prepare_inputs(self, inputs: np.ndarray) -> torch.Tensor:
        """Format input numpy array to Torch tensor with (N, C, H, W)."""
        arr = np.array(inputs)
        if arr.dtype == np.uint8:
            arr = arr.astype(np.float32) / 255.0
        elif arr.dtype != np.float32:
            arr = arr.astype(np.float32)

        if arr.ndim == 4 and arr.shape[-1] in (1, 3):
            arr = np.transpose(arr, (0, 3, 1, 2))

        return torch.from_numpy(arr)

    def predict(self, inputs: np.ndarray) -> np.ndarray:
        """Execute forward pass on TorchScript model."""
        if self._model is None:
            self.load()

        assert self._model is not None
        tensor_in = self._prepare_inputs(inputs)

        with torch.no_grad():
            out = self._model(tensor_in)

        if isinstance(out, (list, tuple)):
            out = out[0]
        elif isinstance(out, dict):
            out = next(iter(out.values()))

        if isinstance(out, torch.Tensor):
            return out.detach().cpu().numpy().astype(np.float32)

        return np.array(out, dtype=np.float32)

    def fingerprint(self) -> Dict[str, Any]:
        """Generate deterministic structural fingerprint of parameters."""
        if self._model is None:
            self.load()

        assert self._model is not None

        param_hashes = []
        for name, param in sorted(self._model.named_parameters()):
            p_bytes = param.detach().cpu().numpy().tobytes()
            param_hashes.append({
                "name": name,
                "shape": list(param.shape),
                "sha256": hash_bytes(p_bytes),
            })

        digest = canonical_json_hash({"params": param_hashes})
        return {
            "graph_digest": digest,
            "parameter_tensors": len(param_hashes),
        }

    def close(self) -> None:
        self._model = None
