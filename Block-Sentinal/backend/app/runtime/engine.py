"""Real Model Runtime & Inference Execution Engine with State Machine and Provenance Binding."""
from datetime import datetime, timezone
import json
from pathlib import Path
import time
from typing import Any, Dict, List, Optional, Tuple, Union
import uuid

import numpy as np
import onnx
import onnxruntime as ort
from PIL import Image

from app.core.config import settings
from app.crypto.canonical import canonical_json_hash, hash_bytes, hash_file
from app.inference.dna import InferenceDNAGenerator, default_dna_generator
from app.models_engine.adapters.onnx_adapter import ONNXAdapter
from app.models_engine.registry import ModelRegistry, default_model_registry
from app.runtime.preprocessor import DeterministicPreprocessor
from app.schemas.inference import (
    InferenceConfigSpec,
    InferenceDNARecord,
    InferenceOutput,
    InputMetadataSpec,
    ModelBindingSpec,
    PreprocessingSpec,
)
from app.schemas.model import ModelFormat, ModelInputSpec, ModelOutputSpec
from app.schemas.runtime import (
    DeterministicPreprocessingRecord,
    ModelRuntimeState,
    ModelValidationReport,
    OutputValidationReport,
    OutputValidationStatus,
    RuntimeExecutionRecord,
    StateTransitionEvent,
)


class ModelRuntimeEngine:
    """Backend-authoritative local ONNX model execution runtime with cryptographic provenance."""

    def __init__(
        self,
        registry: Optional[ModelRegistry] = None,
        dna_generator: Optional[InferenceDNAGenerator] = None,
    ):
        self.registry = registry or default_model_registry
        self.dna_generator = dna_generator or default_dna_generator
        self._session_cache: Dict[str, ort.InferenceSession] = {}
        self._event_logs: Dict[str, List[StateTransitionEvent]] = {}
        self._current_states: Dict[str, ModelRuntimeState] = {}

    def _record_transition(
        self,
        key: str,
        from_state: ModelRuntimeState,
        to_state: ModelRuntimeState,
        reason: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> StateTransitionEvent:
        """Log state transition event in the runtime lifecycle."""
        evt = StateTransitionEvent(
            timestamp=datetime.now(timezone.utc),
            from_state=from_state,
            to_state=to_state,
            reason=reason,
            details=details or {},
        )
        if key not in self._event_logs:
            self._event_logs[key] = []
        self._event_logs[key].append(evt)
        self._current_states[key] = to_state
        return evt

    def get_state(self, key: str) -> ModelRuntimeState:
        """Get current state of a model or execution pipeline."""
        return self._current_states.get(key, ModelRuntimeState.DISCOVERED)

    def get_lifecycle_history(self, key: str) -> List[StateTransitionEvent]:
        """Retrieve complete transition audit log for a given model/execution key."""
        return list(self._event_logs.get(key, []))

    # =========================================================================
    # 1. Model Validation
    # =========================================================================

    def validate_model(
        self,
        model_path: Union[str, Path],
        model_id: Optional[str] = None,
    ) -> ModelValidationReport:
        """Verify model file exists, compute SHA-256, parse architecture, and inspect tensor contracts."""
        path = Path(model_path).resolve()
        key = model_id or str(path)

        prev_state = self.get_state(key)
        self._record_transition(
            key, prev_state, ModelRuntimeState.VALIDATING, f"Initiating structural validation on {path.name}"
        )

        if not path.is_file():
            self._record_transition(
                key, ModelRuntimeState.VALIDATING, ModelRuntimeState.UNAVAILABLE, f"File not found: {path}"
            )
            return ModelValidationReport(
                model_id=key,
                model_path=str(path),
                model_sha256="0" * 64,
                format=ModelFormat.UNSUPPORTED,
                is_valid=False,
                state=ModelRuntimeState.UNAVAILABLE,
                validation_errors=[f"Model file does not exist at {path}"],
            )

        model_sha256 = hash_file(str(path))

        # Check format and parse ONNX proto
        try:
            model_proto = onnx.load(str(path), load_external_data=False)
            onnx.checker.check_model(model_proto)
        except Exception as exc:
            err_msg = f"ONNX proto validation failed: {str(exc)}"
            self._record_transition(
                key, ModelRuntimeState.VALIDATING, ModelRuntimeState.INVALID, err_msg
            )
            return ModelValidationReport(
                model_id=key,
                model_path=str(path),
                model_sha256=model_sha256,
                format=ModelFormat.ONNX,
                is_valid=False,
                state=ModelRuntimeState.INVALID,
                validation_errors=[err_msg],
            )

        # Inspect input & output specifications
        input_specs: List[ModelInputSpec] = []
        for inp in model_proto.graph.input:
            shape: List[Optional[int]] = []
            tensor_type = inp.type.tensor_type
            if tensor_type.HasField("shape"):
                for dim in tensor_type.shape.dim:
                    if dim.HasField("dim_value") and dim.dim_value > 0:
                        shape.append(dim.dim_value)
                    else:
                        shape.append(None)
            elem_type = onnx.TensorProto.DataType.Name(tensor_type.elem_type) if tensor_type.elem_type else "float32"
            input_specs.append(ModelInputSpec(name=inp.name, shape=shape, data_type=elem_type))

        output_specs: List[ModelOutputSpec] = []
        for out in model_proto.graph.output:
            shape: List[Optional[int]] = []
            tensor_type = out.type.tensor_type
            if tensor_type.HasField("shape"):
                for dim in tensor_type.shape.dim:
                    if dim.HasField("dim_value") and dim.dim_value > 0:
                        shape.append(dim.dim_value)
                    else:
                        shape.append(None)
            elem_type = onnx.TensorProto.DataType.Name(tensor_type.elem_type) if tensor_type.elem_type else "float32"
            output_specs.append(ModelOutputSpec(name=out.name, shape=shape, data_type=elem_type))

        # Count parameters
        parameter_count = 0
        for init in model_proto.graph.initializer:
            p_dim = 1
            for d in init.dims:
                p_dim *= d
            parameter_count += p_dim

        node_count = len(model_proto.graph.node)

        arch_meta = {
            "producer_name": model_proto.producer_name,
            "producer_version": model_proto.producer_version,
            "ir_version": model_proto.ir_version,
            "opset_imports": {
                op.domain or "ai.onnx": op.version for op in model_proto.opset_import
            },
            "initializer_count": len(model_proto.graph.initializer),
        }

        self._record_transition(
            key, ModelRuntimeState.VALIDATING, ModelRuntimeState.VALID,
            f"ONNX model {path.name} validated successfully ({node_count} nodes, {parameter_count} params)."
        )

        return ModelValidationReport(
            model_id=key,
            model_path=str(path),
            model_sha256=model_sha256,
            format=ModelFormat.ONNX,
            is_valid=True,
            state=ModelRuntimeState.VALID,
            parameter_count=parameter_count,
            node_count=node_count,
            layer_count=node_count,
            input_specs=input_specs,
            output_specs=output_specs,
            architecture_metadata=arch_meta,
            validation_errors=[],
        )

    # =========================================================================
    # 2. Runtime Loading
    # =========================================================================

    def load_session(
        self,
        model_path: Union[str, Path],
        model_id: Optional[str] = None,
    ) -> ort.InferenceSession:
        """Create and cache onnxruntime.InferenceSession with CPU execution provider."""
        path = Path(model_path).resolve()
        cache_key = str(path)

        if cache_key in self._session_cache:
            return self._session_cache[cache_key]

        key = model_id or cache_key
        prev_state = self.get_state(key)
        self._record_transition(
            key, prev_state, ModelRuntimeState.RUNTIME_LOADING, f"Loading InferenceSession for {path.name}"
        )

        opts = ort.SessionOptions()
        opts.inter_op_num_threads = 1
        opts.intra_op_num_threads = 1
        opts.log_severity_level = 3  # Error only

        try:
            session = ort.InferenceSession(
                str(path),
                sess_options=opts,
                providers=["CPUExecutionProvider"],
            )
            self._session_cache[cache_key] = session
            self._record_transition(
                key, ModelRuntimeState.RUNTIME_LOADING, ModelRuntimeState.RUNTIME_READY,
                f"InferenceSession ready with provider {session.get_providers()[0]}"
            )
            return session
        except Exception as exc:
            err_msg = f"Failed to initialize onnxruntime session: {str(exc)}"
            self._record_transition(
                key, ModelRuntimeState.RUNTIME_LOADING, ModelRuntimeState.FAILED, err_msg
            )
            raise RuntimeError(err_msg)

    # =========================================================================
    # 3. Real Inference Execution & Output Validation
    # =========================================================================

    def execute_inference(
        self,
        model_path: Union[str, Path],
        image_input: Union[bytes, Image.Image, np.ndarray],
        model_id: Optional[str] = None,
        preprocessing_id: Optional[str] = None,
        preprocessing_override: Optional[Dict[str, Any]] = None,
        inference_config: Optional[Dict[str, Any]] = None,
    ) -> Tuple[RuntimeExecutionRecord, InferenceDNARecord, np.ndarray]:
        """Execute model forward pass via onnxruntime, validate output integrity, and seal provenance."""
        path = Path(model_path).resolve()
        exec_key = model_id or path.stem

        # 1. Validate Model
        val_report = self.validate_model(path, model_id=exec_key)
        if not val_report.is_valid:
            raise RuntimeError(
                f"INFERENCE = UNAVAILABLE: Model validation failed. Errors: {val_report.validation_errors}"
            )

        # 2. Load Runtime Session
        session = self.load_session(path, model_id=exec_key)
        input_meta = session.get_inputs()[0]

        # 3. Preprocess Input Deterministically
        input_spec = ModelInputSpec(
            name=input_meta.name,
            shape=[d if isinstance(d, int) and d > 0 else None for d in input_meta.shape],
            data_type=str(input_meta.type),
        )

        tensor_arr, prep_rec, input_sha256 = DeterministicPreprocessor.preprocess_image(
            image_input=image_input,
            input_spec=input_spec,
            preprocessing_id=preprocessing_id,
            user_override=preprocessing_override,
        )

        # 4. State Transition -> EXECUTING
        self._record_transition(
            exec_key, ModelRuntimeState.RUNTIME_READY, ModelRuntimeState.EXECUTING,
            f"Executing forward pass on input tensor shape {list(tensor_arr.shape)}"
        )

        started_at = datetime.now(timezone.utc)
        t0 = time.perf_counter()

        try:
            raw_outputs = session.run(None, {input_meta.name: tensor_arr})
            latency_ms = round((time.perf_counter() - t0) * 1000.0, 3)
            completed_at = datetime.now(timezone.utc)
        except Exception as exc:
            err_msg = f"Runtime execution failed: {str(exc)}"
            self._record_transition(exec_key, ModelRuntimeState.EXECUTING, ModelRuntimeState.FAILED, err_msg)
            raise RuntimeError(err_msg)

        # 5. Extract Output Tensor
        if not raw_outputs or len(raw_outputs) == 0:
            err_msg = "INFERENCE_VALIDATION = FAILED: Output tensor does not exist or empty."
            self._record_transition(exec_key, ModelRuntimeState.EXECUTING, ModelRuntimeState.FAILED, err_msg)
            raise RuntimeError(err_msg)

        output_arr = np.array(raw_outputs[0])

        # 6. Output Validation
        discrepancies: List[str] = []
        all_finite = bool(np.all(np.isfinite(output_arr)))
        if not all_finite:
            discrepancies.append("Output tensor contains non-finite values (NaN or Inf).")

        expected_out_meta = session.get_outputs()[0]
        expected_shape = expected_out_meta.shape
        shape_matches = True
        if len(expected_shape) == len(output_arr.shape):
            for exp_d, act_d in zip(expected_shape, output_arr.shape):
                if isinstance(exp_d, int) and exp_d > 0 and exp_d != act_d:
                    shape_matches = False
                    discrepancies.append(f"Output shape mismatch: expected {expected_shape}, got {output_arr.shape}")
                    break

        output_sha256 = hash_bytes(output_arr.tobytes())
        val_status = OutputValidationStatus.PASSED if (all_finite and shape_matches) else OutputValidationStatus.FAILED

        val_report_out = OutputValidationReport(
            output_exists=True,
            dtype_valid=str(output_arr.dtype) in ("float32", "float64", "int32", "int64", "uint8"),
            shape_matches_schema=shape_matches,
            all_values_finite=all_finite,
            serializable=True,
            output_sha256=output_sha256,
            validation_status=val_status,
            discrepancies=discrepancies,
        )

        if val_status == OutputValidationStatus.FAILED:
            err_msg = f"INFERENCE_VALIDATION = FAILED: {'; '.join(discrepancies)}"
            self._record_transition(exec_key, ModelRuntimeState.EXECUTING, ModelRuntimeState.FAILED, err_msg)
            raise RuntimeError(err_msg)

        # State Transition -> COMPLETED
        self._record_transition(
            exec_key, ModelRuntimeState.EXECUTING, ModelRuntimeState.COMPLETED,
            f"Inference completed successfully in {latency_ms:.2f}ms."
        )

        # 7. Compute Tensor Summary Statistics
        flat = output_arr.flatten()
        output_summary = {
            "min": float(np.min(flat)),
            "max": float(np.max(flat)),
            "mean": float(np.mean(flat)),
            "std": float(np.std(flat)),
            "elements": int(flat.size),
        }

        # 8. Cryptographic Binding: Inference DNA
        inference_id = f"infer_{uuid.uuid4().hex[:12]}"
        dna_record = self.dna_generator.create_dna_record(
            model_id=exec_key,
            model_hash=val_report.model_sha256,
            input_hash=input_sha256,
            preprocessing_hash=prep_rec.preprocessing_hash,
            output_hash=output_sha256,
            inference_config=inference_config or {"device": "cpu", "provider": "CPUExecutionProvider"},
            record_id=inference_id,
        )

        # 9. Construct Runtime Execution Record
        execution_record = RuntimeExecutionRecord(
            inference_id=inference_id,
            model_id=exec_key,
            model_sha256=val_report.model_sha256,
            fingerprint_id=val_report.model_sha256[:16],
            runtime="onnxruntime",
            runtime_version=ort.__version__,
            architecture=val_report.architecture_metadata.get("producer_name", "ONNX"),
            input_signature=[s.model_dump() for s in val_report.input_specs],
            output_signature=[s.model_dump() for s in val_report.output_specs],
            preprocessing_config=prep_rec.model_dump(mode="json"),
            input_sha256=input_sha256,
            output_sha256=output_sha256,
            started_at=started_at,
            completed_at=completed_at,
            latency_ms=latency_ms,
            output_shape=list(output_arr.shape),
            output_dtype=str(output_arr.dtype),
            output_summary=output_summary,
            validation_report=val_report_out,
            lifecycle_history=self.get_lifecycle_history(exec_key),
        )

        return execution_record, dna_record, output_arr


default_runtime_engine = ModelRuntimeEngine()
