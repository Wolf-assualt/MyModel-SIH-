"""Model inspectors extracting real structural metadata, tensor dimensions, and parameter statistics."""
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict

from app.models_engine.adapters.factory import ModelAdapterFactory
from app.models_engine.adapters.onnx_adapter import ONNXAdapter
from app.schemas.model import ModelFormat


class BaseModelInspector(ABC):
    """Abstract base class for framework-specific model inspectors."""

    @abstractmethod
    def inspect(self, model_path: Path) -> Dict[str, Any]:
        """Inspect model binary and return real structural metadata."""
        pass


class ONNXInspector(BaseModelInspector):
    """Inspects ONNX graphs extracting real node count, tensor shapes, inputs, and outputs."""

    def inspect(self, model_path: Path) -> Dict[str, Any]:
        path = Path(model_path)
        if not path.is_file():
            raise FileNotFoundError(f"Model file not found: {model_path}")

        adapter = ONNXAdapter(path)
        adapter.load()
        meta = adapter.metadata()

        return {
            "parameter_count": meta["parameter_count"],
            "node_count": meta["node_count"],
            "layer_count": meta["layer_count"],
            "inputs": adapter.input_schema(),
            "outputs": adapter.output_schema(),
            "metadata": meta,
            "access_mode": adapter.access_mode.value,
        }


class PyTorchInspector(BaseModelInspector):
    """Inspects PyTorch weights safely using PyTorchAdapter."""

    def inspect(self, model_path: Path) -> Dict[str, Any]:
        path = Path(model_path)
        if not path.is_file():
            raise FileNotFoundError(f"Model file not found: {model_path}")

        from app.models_engine.adapters.pytorch_adapter import PyTorchAdapter

        try:
            adapter = PyTorchAdapter(path)
            adapter.load()
            meta = adapter.metadata()
        except Exception as exc:
            raise ValueError(f"Secure PyTorch deserialization failed: {exc}")

        return {
            "parameter_count": meta.get("parameter_count", 0),
            "node_count": meta.get("node_count", 0),
            "layer_count": meta.get("layer_count", 0),
            "inputs": adapter.input_schema(),
            "outputs": adapter.output_schema(),
            "metadata": meta,
            "access_mode": adapter.access_mode.value,
        }


class GenericModelInspector(BaseModelInspector):
    """Real model inspector delegating to safe framework-specific adapters."""

    def inspect(self, model_path: Path, format_hint: ModelFormat = ModelFormat.GENERIC_BINARY) -> Dict[str, Any]:
        path = Path(model_path)
        if not path.is_file():
            raise FileNotFoundError(f"Model file not found: {model_path}")

        adapter = ModelAdapterFactory.get_adapter(path, format_hint=format_hint)
        adapter.load()
        meta = adapter.metadata()

        return {
            "parameter_count": meta.get("parameter_count", 0),
            "node_count": meta.get("node_count", 0),
            "layer_count": meta.get("layer_count", 0),
            "inputs": adapter.input_schema(),
            "outputs": adapter.output_schema(),
            "metadata": meta,
            "access_mode": adapter.access_mode.value,
        }
