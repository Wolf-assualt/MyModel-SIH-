"""Real ONNX Model Adapter powered by ONNX Runtime and ONNX Proto inspection."""
from pathlib import Path
from typing import Any, Dict, List, Optional
import numpy as np
from PIL import Image

import onnx
import onnxruntime as ort

from app.crypto.canonical import canonical_json_hash, hash_bytes
from app.models_engine.adapters.base import BaseModelAdapter
from app.schemas.model import AccessMode, ModelFormat, ModelInputSpec, ModelOutputSpec


class ONNXAdapter(BaseModelAdapter):
    """Adapter for ONNX models performing safe local graph inspection and runtime inference."""

    def __init__(self, model_path: Path):
        super().__init__(model_path)
        self._model_proto: Optional[onnx.ModelProto] = None
        self._session: Optional[ort.InferenceSession] = None
        self._inputs_meta: List[ModelInputSpec] = []
        self._outputs_meta: List[ModelOutputSpec] = []

    @property
    def format(self) -> ModelFormat:
        return ModelFormat.ONNX

    @property
    def access_mode(self) -> AccessMode:
        return AccessMode.WHITE_BOX

    def load(self) -> None:
        """Load ONNX proto for graph inspection and initialize InferenceSession."""
        if self._session is not None and self._model_proto is not None:
            return

        # 1. Parse ONNX Graph Proto
        self._model_proto = onnx.load(str(self.model_path), load_external_data=False)

        # 2. Extract inputs and outputs from proto/runtime
        opts = ort.SessionOptions()
        opts.inter_op_num_threads = 1
        opts.intra_op_num_threads = 1
        opts.log_severity_level = 3  # Error only
        self._session = ort.InferenceSession(
            str(self.model_path),
            sess_options=opts,
            providers=["CPUExecutionProvider"],
        )

        self._inputs_meta = []
        for inp in self._session.get_inputs():
            shape: List[Optional[int]] = []
            for dim in inp.shape:
                if isinstance(dim, int) and dim > 0:
                    shape.append(dim)
                else:
                    shape.append(None)
            self._inputs_meta.append(
                ModelInputSpec(
                    name=inp.name,
                    shape=shape,
                    data_type=str(inp.type),
                )
            )

        self._outputs_meta = []
        for out in self._session.get_outputs():
            shape = []
            for dim in out.shape:
                if isinstance(dim, int) and dim > 0:
                    shape.append(dim)
                else:
                    shape.append(None)
            self._outputs_meta.append(
                ModelOutputSpec(
                    name=out.name,
                    shape=shape,
                    data_type=str(out.type),
                )
            )

    def metadata(self) -> Dict[str, Any]:
        """Extract architectural parameters, node counts, and initializer statistics."""
        if self._model_proto is None:
            self.load()

        assert self._model_proto is not None
        graph = self._model_proto.graph

        node_types: Dict[str, int] = {}
        for node in graph.node:
            node_types[node.op_type] = node_types.get(node.op_type, 0) + 1

        parameter_count = 0
        initializer_names = []
        for init in graph.initializer:
            initializer_names.append(init.name)
            dims = list(init.dims)
            count = 1
            for d in dims:
                count *= d
            parameter_count += count

        opset_imports = {
            op.domain or "ai.onnx": op.version
            for op in self._model_proto.opset_import
        }

        return {
            "parameter_count": parameter_count,
            "node_count": len(graph.node),
            "layer_count": len(graph.node),
            "node_types": node_types,
            "opset_imports": opset_imports,
            "ir_version": self._model_proto.ir_version,
            "producer_name": self._model_proto.producer_name,
            "producer_version": self._model_proto.producer_version,
            "initializer_count": len(graph.initializer),
        }

    def input_schema(self) -> List[ModelInputSpec]:
        if not self._inputs_meta:
            self.load()
        return self._inputs_meta

    def output_schema(self) -> List[ModelOutputSpec]:
        if not self._outputs_meta:
            self.load()
        return self._outputs_meta

    def _prepare_inputs(self, inputs: np.ndarray) -> np.ndarray:
        """Format input numpy array to match expected model input dimensions and type."""
        if not self._inputs_meta:
            self.load()

        first_input = self._inputs_meta[0]
        expected_shape = first_input.shape

        arr = np.array(inputs)
        # Ensure float32 if uint8 image
        if arr.dtype == np.uint8:
            arr = arr.astype(np.float32) / 255.0
        elif arr.dtype != np.float32:
            arr = arr.astype(np.float32)

        # Shape handling: standard CV models expect NCHW
        # If input is NHWC (e.g. N, H, W, 3), convert to NCHW (N, 3, H, W)
        if arr.ndim == 4 and arr.shape[-1] in (1, 3) and (len(expected_shape) == 4 and expected_shape[1] in (1, 3, None)):
            arr = np.transpose(arr, (0, 3, 1, 2))

        # Check spatial dimensions if model specifies fixed H and W
        if len(expected_shape) == 4:
            target_h = expected_shape[2]
            target_w = expected_shape[3]
            if target_h is not None and target_w is not None:
                current_h, current_w = arr.shape[2], arr.shape[3]
                if (current_h, current_w) != (target_h, target_w):
                    resized = []
                    for i in range(arr.shape[0]):
                        # arr[i] is (C, H, W)
                        img_c = arr[i].transpose(1, 2, 0)
                        pil = Image.fromarray((np.clip(img_c, 0, 1) * 255).astype(np.uint8))
                        pil = pil.resize((target_w, target_h), Image.Resampling.BILINEAR)
                        r_arr = np.array(pil, dtype=np.float32) / 255.0
                        if r_arr.ndim == 2:
                            r_arr = np.expand_dims(r_arr, axis=-1)
                        resized.append(r_arr.transpose(2, 0, 1))
                    arr = np.array(resized, dtype=np.float32)

        return arr

    def predict(self, inputs: np.ndarray) -> np.ndarray:
        """Execute real model forward pass via ONNX Runtime."""
        if self._session is None:
            self.load()

        assert self._session is not None
        input_meta = self._session.get_inputs()[0]
        prepared = self._prepare_inputs(inputs)

        outputs = self._session.run(None, {input_meta.name: prepared})
        output_arr = np.array(outputs[0], dtype=np.float32)
        return output_arr

    def fingerprint(self) -> Dict[str, Any]:
        """Compute structural fingerprint based on initializers and node graph structure."""
        if self._model_proto is None:
            self.load()

        assert self._model_proto is not None
        graph = self._model_proto.graph

        # Deterministic representation of nodes and initializers
        node_summary = [
            {"op": n.op_type, "inputs": list(n.input), "outputs": list(n.output)}
            for n in graph.node
        ]
        initializer_hashes = []
        for init in graph.initializer:
            raw_bytes = init.raw_data if init.raw_data else bytes(init.float_data)
            init_hash = hash_bytes(raw_bytes) if raw_bytes else ""
            initializer_hashes.append({
                "name": init.name,
                "dims": list(init.dims),
                "data_type": init.data_type,
                "hash": init_hash,
            })

        digest = canonical_json_hash({
            "nodes": node_summary,
            "initializers": initializer_hashes,
        })

        return {
            "graph_digest": digest,
            "node_count": len(graph.node),
            "initializer_count": len(graph.initializer),
        }

    def close(self) -> None:
        """Release session memory."""
        self._session = None
        self._model_proto = None
