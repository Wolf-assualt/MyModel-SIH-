"""Model Registry managing cryptographic identity, structural metadata, and baseline audits."""
import json
import uuid
from pathlib import Path
from typing import Optional

from app.core.config import settings
from app.crypto.canonical import canonical_json_dumps, canonical_json_hash, hash_file
from app.models_engine.inspectors import GenericModelInspector, ONNXInspector
from app.schemas.base import AssetStatus
from app.schemas.model import (
    ModelFormat,
    ModelIdentityManifest,
    ModelVerifyResponse,
)


class ModelRegistry:
    """Manages model registration, deterministic identity hashing, and baseline verification."""

    def __init__(self, base_dir: Optional[Path] = None):
        if base_dir:
            self.base_dir = Path(base_dir)
        else:
            self.base_dir = Path(settings.DATA_DIR) / "models"

        self.manifests_dir = self.base_dir / "manifests"
        self.baselines_dir = self.base_dir / "baselines"

        self.manifests_dir.mkdir(parents=True, exist_ok=True)
        self.baselines_dir.mkdir(parents=True, exist_ok=True)

        self.onnx_inspector = ONNXInspector()
        self.generic_inspector = GenericModelInspector()

    def _get_inspector(self, model_format: ModelFormat):
        if model_format == ModelFormat.ONNX:
            return self.onnx_inspector
        return self.generic_inspector

    def register_model(
        self,
        name: str,
        version: str,
        model_path: Path,
        format: ModelFormat,
        is_reference: bool = False,
    ) -> ModelIdentityManifest:
        """Inspect model binary, calculate canonical identity digest, and persist manifest."""
        path = Path(model_path)
        if not path.is_file():
            raise FileNotFoundError(f"Model file not found: {model_path}")

        binary_sha256 = hash_file(str(path))
        inspector = self._get_inspector(format)
        struct_info = inspector.inspect(path)

        identity_payload = {
            "name": name,
            "version": version,
            "parameter_count": struct_info["parameter_count"],
            "layer_count": struct_info["layer_count"],
            "inputs": [inp.model_dump() for inp in struct_info["inputs"]],
            "outputs": [out.model_dump() for out in struct_info["outputs"]],
        }
        identity_digest = canonical_json_hash(identity_payload)

        model_id = str(uuid.uuid4())
        manifest = ModelIdentityManifest(
            model_id=model_id,
            name=name,
            version=version,
            format=format,
            binary_sha256=binary_sha256,
            parameter_count=struct_info["parameter_count"],
            layer_count=struct_info["layer_count"],
            inputs=struct_info["inputs"],
            outputs=struct_info["outputs"],
            metadata=struct_info["metadata"],
            identity_digest=identity_digest,
            status=AssetStatus.ACCEPTED,
        )

        # Persist manifest
        manifest_file = self.manifests_dir / f"{model_id}.json"
        with open(manifest_file, "w", encoding="utf-8") as f:
            f.write(canonical_json_dumps(manifest.model_dump(mode="json")))

        # If designated as reference, also store under baseline name
        if is_reference:
            baseline_file = self.baselines_dir / f"{name}_{version}.json"
            with open(baseline_file, "w", encoding="utf-8") as f:
                f.write(canonical_json_dumps(manifest.model_dump(mode="json")))

        return manifest

    def get_model(self, model_id: str) -> Optional[ModelIdentityManifest]:
        """Load registered model manifest by model_id."""
        manifest_file = self.manifests_dir / f"{model_id}.json"
        if not manifest_file.is_file():
            return None

        with open(manifest_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        return ModelIdentityManifest(**data)

    def get_baseline(self, name: str, version: str) -> Optional[ModelIdentityManifest]:
        """Load reference baseline manifest by model name and version."""
        baseline_file = self.baselines_dir / f"{name}_{version}.json"
        if not baseline_file.is_file():
            return None

        with open(baseline_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        return ModelIdentityManifest(**data)

    def verify_against_baseline(
        self,
        model_id: str,
        baseline_id: Optional[str] = None,
    ) -> ModelVerifyResponse:
        """Verify candidate model's binary digest and structural layout against reference baseline."""
        candidate = self.get_model(model_id)
        if not candidate:
            raise FileNotFoundError(f"Candidate model {model_id} not found in registry.")

        if baseline_id:
            baseline = self.get_model(baseline_id)
        else:
            baseline = self.get_baseline(candidate.name, candidate.version)

        if not baseline:
            return ModelVerifyResponse(
                model_id=model_id,
                is_valid=False,
                binary_match=False,
                structural_match=False,
                discrepancies=["No registered reference baseline found for this model."],
            )

        discrepancies = []

        binary_match = candidate.binary_sha256 == baseline.binary_sha256
        if not binary_match:
            discrepancies.append(
                f"Binary SHA-256 mismatch: candidate={candidate.binary_sha256[:16]}... vs baseline={baseline.binary_sha256[:16]}..."
            )

        structural_match = candidate.identity_digest == baseline.identity_digest
        if not structural_match:
            discrepancies.append(
                f"Structural identity mismatch: candidate={candidate.identity_digest[:16]}... vs baseline={baseline.identity_digest[:16]}..."
            )

        if candidate.parameter_count != baseline.parameter_count:
            discrepancies.append(
                f"Parameter count mismatch: candidate={candidate.parameter_count} vs baseline={baseline.parameter_count}"
            )

        if candidate.layer_count != baseline.layer_count:
            discrepancies.append(
                f"Layer count mismatch: candidate={candidate.layer_count} vs baseline={baseline.layer_count}"
            )

        if candidate.inputs != baseline.inputs:
            discrepancies.append("Input tensor specifications do not match baseline")

        if candidate.outputs != baseline.outputs:
            discrepancies.append("Output tensor specifications do not match baseline")

        is_valid = binary_match and structural_match and (len(discrepancies) == 0)

        return ModelVerifyResponse(
            model_id=model_id,
            is_valid=is_valid,
            binary_match=binary_match,
            structural_match=structural_match,
            discrepancies=discrepancies,
        )


default_model_registry = ModelRegistry()
