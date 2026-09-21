"""Adapter Factory for automatic model detection and adapter instantiation."""
from pathlib import Path
from typing import Callable, Optional
import zipfile
import numpy as np

from app.models_engine.adapters.base import BaseModelAdapter
from app.models_engine.adapters.blackbox_adapter import BlackBoxAdapter
from app.models_engine.adapters.generic_binary_adapter import GenericBinaryAdapter
from app.models_engine.adapters.onnx_adapter import ONNXAdapter
from app.models_engine.adapters.pytorch_adapter import PyTorchAdapter
from app.models_engine.adapters.torchscript_adapter import TorchScriptAdapter
from app.schemas.model import ModelFormat


class ModelAdapterFactory:
    """Detects model formats safely and creates appropriate BaseModelAdapter instances."""

    @staticmethod
    def detect_format(model_path: Path) -> ModelFormat:
        """Detect format from file extensions and file header inspection."""
        path = Path(model_path)
        if not path.is_file():
            raise FileNotFoundError(f"Model file not found: {path}")

        suffix = path.suffix.lower()

        # Check for ONNX
        if suffix == ".onnx":
            return ModelFormat.ONNX

        # Check for TorchScript vs PyTorch weights in zip/tar
        if suffix in (".pt", ".pth", ".bin", ".ts"):
            # Check if it's a TorchScript archive
            if zipfile.is_zipfile(str(path)):
                try:
                    with zipfile.ZipFile(str(path), "r") as zf:
                        names = zf.namelist()
                        if any("code" in n or "model.json" in n or "constants.pkl" in n for n in names):
                            return ModelFormat.TORCHSCRIPT
                except Exception:
                    pass
            # Default to PyTorch weights format for .pt / .pth
            return ModelFormat.PYTORCH_WEIGHTS

        return ModelFormat.UNSUPPORTED

    @classmethod
    def get_adapter(
        cls,
        model_path: Path,
        format_hint: Optional[ModelFormat] = None,
        predict_fn: Optional[Callable[[np.ndarray], np.ndarray]] = None,
    ) -> BaseModelAdapter:
        """Instantiate appropriate adapter for the given model path."""
        path = Path(model_path)

        if format_hint == ModelFormat.BLACK_BOX or predict_fn is not None:
            return BlackBoxAdapter(path, predict_fn=predict_fn)

        fmt = format_hint if format_hint and format_hint != ModelFormat.UNSUPPORTED else cls.detect_format(path)

        if fmt == ModelFormat.ONNX:
            return ONNXAdapter(path)
        elif fmt == ModelFormat.TORCHSCRIPT:
            return TorchScriptAdapter(path)
        elif fmt == ModelFormat.PYTORCH_WEIGHTS:
            return PyTorchAdapter(path)
        elif fmt == ModelFormat.GENERIC_BINARY:
            # Check if it's actually an ONNX, TorchScript, or PyTorch binary despite the name
            try:
                adapter = ONNXAdapter(path)
                adapter.load()
                return adapter
            except Exception:
                pass
            try:
                adapter = TorchScriptAdapter(path)
                adapter.load()
                return adapter
            except Exception:
                pass
            try:
                adapter = PyTorchAdapter(path)
                adapter.load()
                return adapter
            except Exception:
                pass
            # Safely fall back to GenericBinaryAdapter for static integrity assurance
            return GenericBinaryAdapter(path)
        else:
            raise ValueError(f"UNSUPPORTED_FORMAT: Model format {fmt} is not safely supported locally.")
