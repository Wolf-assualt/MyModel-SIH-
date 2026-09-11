"""Model Registry managing cryptographic identity, structural metadata, and baseline audits."""
import json
import uuid
from pathlib import Path
from typing import Any, Optional, Union

from app.core.config import settings
from app.crypto.canonical import canonical_json_dumps, canonical_json_hash, hash_file
from app.crypto.signer import KeyManager, default_key_manager
from app.db.session import SessionLocal
from app.models.model import Model as DBModel, ModelFingerprint as DBModelFingerprint
from app.models_engine.inspectors import GenericModelInspector, ONNXInspector, PyTorchInspector
from app.schemas.base import AssetStatus
from app.schemas.model import (
    LayerHashInfo,
    ModelFormat,
    ModelIdentityManifest,
    ModelVerifyResponse,
)


class ModelRegistry:
    """Manages model registration, deterministic identity hashing, ECDSA signing, and baseline verification."""

    def __init__(self, base_dir: Optional[Path] = None, key_manager: Optional[KeyManager] = None):
        if base_dir:
            self.base_dir = Path(base_dir)
        else:
            self.base_dir = Path(settings.DATA_DIR) / "models"

        self.manifests_dir = self.base_dir / "manifests"
        self.baselines_dir = self.base_dir / "baselines"

        self.manifests_dir.mkdir(parents=True, exist_ok=True)
        self.baselines_dir.mkdir(parents=True, exist_ok=True)

        self.onnx_inspector = ONNXInspector()
        self.pytorch_inspector = PyTorchInspector()
        self.generic_inspector = GenericModelInspector()
        self.key_manager = key_manager or default_key_manager

    def _get_inspector(self, model_format: ModelFormat):
        if model_format == ModelFormat.ONNX:
            return self.onnx_inspector
        elif model_format in (ModelFormat.PYTORCH_WEIGHTS, ModelFormat.TORCHSCRIPT):
            return self.pytorch_inspector
        return self.generic_inspector

    def register_model(
        self,
        name: str,
        version: str,
        model_path: Path,
        format: Any,
        is_reference: bool = False,
    ) -> ModelIdentityManifest:
        """Inspect model binary, calculate canonical identity digest, sign with ECDSA, and register in DB."""
        if isinstance(format, str):
            try:
                format = ModelFormat(format)
            except ValueError:
                if format.upper() in ("PYTORCH", "PYTORCH_WEIGHTS", "PT", "PTH"):
                    format = ModelFormat.PYTORCH_WEIGHTS
                elif format.upper() in ("ONNX",):
                    format = ModelFormat.ONNX
                elif format.upper() in ("TORCHSCRIPT", "TS"):
                    format = ModelFormat.TORCHSCRIPT
                else:
                    format = ModelFormat.GENERIC_BINARY

        path = Path(model_path)
        if not path.is_file():
            raise FileNotFoundError(f"Model file not found: {model_path}")

        binary_sha256 = hash_file(str(path))
        inspector = self._get_inspector(format)
        struct_info = inspector.inspect(path)

        layers: list[LayerHashInfo] = struct_info.get("layers", [])
        architecture_hash = struct_info.get("architecture_hash", "")
        weights_hash = struct_info.get("weights_hash", "")

        identity_payload = {
            "name": name,
            "version": version,
            "format": format.value,
            "binary_sha256": binary_sha256,
            "architecture_hash": architecture_hash,
            "weights_hash": weights_hash,
            "parameter_count": struct_info["parameter_count"],
            "layer_count": struct_info["layer_count"],
            "inputs": [inp.model_dump() for inp in struct_info["inputs"]],
            "outputs": [out.model_dump() for out in struct_info["outputs"]],
        }
        identity_digest = canonical_json_hash(identity_payload)

        # Generate ECDSA SECP256R1 signature of identity digest
        signature = self.key_manager.sign_hash(identity_digest)

        model_id = str(uuid.uuid4())
        manifest = ModelIdentityManifest(
            model_id=model_id,
            name=name,
            version=version,
            format=format,
            binary_sha256=binary_sha256,
            architecture_hash=architecture_hash,
            weights_hash=weights_hash,
            parameter_count=struct_info["parameter_count"],
            layer_count=struct_info["layer_count"],
            layers=layers,
            inputs=struct_info["inputs"],
            outputs=struct_info["outputs"],
            metadata=struct_info["metadata"],
            identity_digest=identity_digest,
            signature=signature,
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

        # Register in database lineage
        try:
            with SessionLocal() as db:
                db_model = db.query(DBModel).filter(DBModel.id == model_id).first()
                if not db_model:
                    db_model = DBModel(
                        id=model_id,
                        name=name,
                        framework=format.value,
                        format=path.suffix or format.value,
                        version=version,
                        file_path=str(path.resolve()),
                        sha256_digest=binary_sha256,
                        parameters_count=struct_info["parameter_count"],
                        size_bytes=path.stat().st_size,
                        metadata_json=json.dumps(struct_info["metadata"]),
                    )
                    db.add(db_model)

                fingerprint = DBModelFingerprint(
                    id=str(uuid.uuid4()),
                    model_id=model_id,
                    weights_sha256=weights_hash or binary_sha256,
                    benchmark_digest=identity_digest,
                )
                db.add(fingerprint)
                db.commit()
        except Exception:
            # DB logging is best effort in testing environments
            pass

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
        """Verify candidate model's binary digest, architecture, weights, and signature against reference baseline."""
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
                weights_match=False,
                signature_valid=False,
                discrepancies=["No registered reference baseline found for this model."],
            )

        discrepancies = []

        # 1. Binary Hash Verification
        binary_match = candidate.binary_sha256 == baseline.binary_sha256
        if not binary_match:
            discrepancies.append(
                f"Binary SHA-256 mismatch: candidate={candidate.binary_sha256[:16]}... vs baseline={baseline.binary_sha256[:16]}..."
            )

        # 2. Structural & Architecture Verification
        structural_match = True
        if candidate.architecture_hash and baseline.architecture_hash:
            if candidate.architecture_hash != baseline.architecture_hash:
                structural_match = False
                discrepancies.append(
                    f"Architecture hash mismatch: candidate={candidate.architecture_hash[:16]}... vs baseline={baseline.architecture_hash[:16]}..."
                )
        elif candidate.identity_digest != baseline.identity_digest:
            structural_match = False
            discrepancies.append(
                f"Structural identity mismatch: candidate={candidate.identity_digest[:16]}... vs baseline={baseline.identity_digest[:16]}..."
            )

        if candidate.parameter_count != baseline.parameter_count:
            structural_match = False
            discrepancies.append(
                f"Parameter count mismatch: candidate={candidate.parameter_count} vs baseline={baseline.parameter_count}"
            )

        if candidate.layer_count != baseline.layer_count:
            structural_match = False
            discrepancies.append(
                f"Layer count mismatch: candidate={candidate.layer_count} vs baseline={baseline.layer_count}"
            )

        if candidate.inputs != baseline.inputs:
            structural_match = False
            discrepancies.append("Input tensor specifications do not match baseline")

        if candidate.outputs != baseline.outputs:
            structural_match = False
            discrepancies.append("Output tensor specifications do not match baseline")

        # 3. Layer-by-Layer Weight Verification
        weights_match = True
        if candidate.weights_hash and baseline.weights_hash:
            if candidate.weights_hash != baseline.weights_hash:
                weights_match = False
                discrepancies.append(
                    f"Weights hash mismatch: candidate={candidate.weights_hash[:16]}... vs baseline={baseline.weights_hash[:16]}..."
                )

                # Pinpoint exact modified layers
                base_layers = {l.name: l.sha256_hash for l in baseline.layers}
                for l in candidate.layers:
                    if l.name in base_layers and l.sha256_hash != base_layers[l.name]:
                        discrepancies.append(f"Layer '{l.name}' weight tensor tampered (hash differed).")
                    elif l.name not in base_layers:
                        discrepancies.append(f"Layer '{l.name}' present in candidate but missing in baseline.")

        # 4. ECDSA Digital Signature Verification
        signature_valid = True
        if candidate.signature:
            pub_pem = self.key_manager.export_public_key_pem()
            signature_valid = KeyManager.verify_signature(pub_pem, candidate.identity_digest, candidate.signature)
            if not signature_valid:
                discrepancies.append("Candidate ECDSA digital signature is invalid or forged.")

        is_valid = binary_match and structural_match and weights_match and signature_valid and (len(discrepancies) == 0)

        return ModelVerifyResponse(
            model_id=model_id,
            is_valid=is_valid,
            binary_match=binary_match,
            structural_match=structural_match,
            weights_match=weights_match,
            signature_valid=signature_valid,
            discrepancies=discrepancies,
        )

    def list_models(self):
        """List all registered models ordered by registered timestamp descending."""
        models = []
        if self.manifests_dir.exists():
            for p in self.manifests_dir.glob("*.json"):
                m = self.get_model(p.stem)
                if m:
                    models.append(m)
        models.sort(key=lambda x: getattr(x, "registered_at", ""), reverse=True)
        return models


default_model_registry = ModelRegistry()

