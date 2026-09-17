"""Red-Team Adversarial Lab runner for executing and verifying attack simulations."""
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
import uuid
from PIL import Image
import numpy as np

from app.core.config import settings
from app.crypto.canonical import canonical_json_hash
from app.inference.dna import InferenceDNAGenerator, default_dna_generator
from app.inference.verifier import InferenceDNAVerifier
from app.integrity.engine import DataIntegrityEngine, default_integrity_engine
from app.models_engine.registry import ModelRegistry, default_model_registry
from app.redteam.generators import DataAttackGenerator
from app.redteam.model_attacks import ModelAttackGenerator
from app.schemas.base import AssetStatus
from app.schemas.dataset import BatchManifest, DatasetFormat, SampleRecord
from app.schemas.inference import InferenceDNARecord, InferenceOutput, PreprocessingSpec
from app.schemas.integrity import IntegrityCheckType
from app.schemas.model import ModelFormat
from app.schemas.redteam import (
    AttackExecutionRequest,
    AttackExecutionResult,
    AttackType,
    AttackVerificationReport,
)


class RedTeamLab:
    """Unified command lab for adversarial attack execution and automated defense verification."""

    def __init__(
        self,
        data_dir: Optional[Path] = None,
        integrity_engine: Optional[DataIntegrityEngine] = None,
        model_registry: Optional[ModelRegistry] = None,
        dna_generator: Optional[InferenceDNAGenerator] = None,
        dna_verifier: Optional[InferenceDNAVerifier] = None,
    ):
        base_dir = data_dir or Path(settings.DATA_DIR)
        self.data_dir = base_dir
        self.quarantine_dir = self.data_dir / "quarantine" / "attacks"
        self.quarantine_models_dir = self.data_dir / "quarantine" / "models"
        self.manifests_dir = self.data_dir / "manifests"

        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.quarantine_models_dir.mkdir(parents=True, exist_ok=True)

        self.data_generator = DataAttackGenerator(quarantine_dir=self.quarantine_dir)
        self.model_generator = ModelAttackGenerator(quarantine_dir=self.quarantine_models_dir)

        self.integrity_engine = integrity_engine or default_integrity_engine
        self.model_registry = model_registry or default_model_registry
        self.dna_generator = dna_generator or default_dna_generator
        self.dna_verifier = dna_verifier or InferenceDNAVerifier()

        # In-memory index of attack execution contexts
        self.attack_contexts: Dict[str, Dict[str, Any]] = {}

    def execute_attack(self, request: AttackExecutionRequest) -> AttackExecutionResult:
        """Executes the requested attack vector in safe quarantine sandbox."""
        attack_id = f"atk_{uuid.uuid4().hex[:12]}"
        executed_at = datetime.now(timezone.utc)

        if request.attack_type == AttackType.LABEL_FLIPPING:
            manifest = self._resolve_or_create_manifest(request.target_entity_id)
            flipped_manifest = self.data_generator.inject_label_flip(
                manifest=manifest,
                flip_ratio=request.intensity,
                new_label=request.target_label or "flipped_class",
            )
            samples_modified = max(1, int(len(manifest.samples) * request.intensity)) if manifest.samples else 0
            attack_sig = canonical_json_hash(flipped_manifest.model_dump(mode="json"))

            res = AttackExecutionResult(
                attack_id=attack_id,
                attack_type=request.attack_type,
                target_entity_id=request.target_entity_id,
                modified_entity_id=flipped_manifest.batch_id,
                samples_modified_count=samples_modified,
                attack_signature=attack_sig,
                description=f"Label flipping attack injected into batch '{manifest.batch_id}' ({samples_modified} samples mutated to '{request.target_label}').",
                executed_at=executed_at,
            )
            self.attack_contexts[attack_id] = {
                "manifest": flipped_manifest,
                "path": self.quarantine_dir / f"{flipped_manifest.batch_id}.json",
            }
            return res

        elif request.attack_type == AttackType.BACKDOOR_TRIGGER:
            manifest = self._resolve_or_create_manifest(request.target_entity_id)
            target_label = request.target_label or "backdoor_target"
            modified_samples: List[SampleRecord] = []
            samples_to_poison = max(2, int(len(manifest.samples) * request.intensity)) if manifest.samples else 2

            for i, sample in enumerate(manifest.samples[:samples_to_poison]):
                img_path = Path(sample.file_path)
                out_img_path = self.quarantine_dir / f"backdoor_sample_{i}_{img_path.name}"
                self.data_generator.inject_backdoor_trigger(
                    image_path=img_path,
                    patch_size=16,
                    output_path=out_img_path,
                )
                poisoned_sample = sample.model_copy(deep=True)
                poisoned_sample.file_path = str(out_img_path)
                poisoned_sample.labels = [{"label": target_label, "confidence": 1.0}]
                poisoned_sample.metadata["backdoor_injected"] = True
                modified_samples.append(poisoned_sample)

            # Combine poisoned samples with remainder of clean samples
            all_samples = modified_samples + manifest.samples[samples_to_poison:]
            poisoned_manifest = BatchManifest(
                batch_id=f"{manifest.batch_id}_backdoored",
                dataset_name=manifest.dataset_name,
                format=manifest.format,
                contributor_id=manifest.contributor_id,
                sample_count=len(all_samples),
                merkle_root=manifest.merkle_root,
                samples=all_samples,
            )

            manifest_path = self.quarantine_dir / f"{poisoned_manifest.batch_id}.json"
            with open(manifest_path, "w", encoding="utf-8") as f:
                json.dump(poisoned_manifest.model_dump(mode="json"), f, indent=2)

            attack_sig = canonical_json_hash(poisoned_manifest.model_dump(mode="json"))

            res = AttackExecutionResult(
                attack_id=attack_id,
                attack_type=request.attack_type,
                target_entity_id=request.target_entity_id,
                modified_entity_id=poisoned_manifest.batch_id,
                samples_modified_count=len(modified_samples),
                attack_signature=attack_sig,
                description=f"Backdoor trigger patch stamped on {len(modified_samples)} samples associated with label '{target_label}'.",
                executed_at=executed_at,
            )
            self.attack_contexts[attack_id] = {
                "manifest": poisoned_manifest,
                "path": manifest_path,
            }
            return res

        elif request.attack_type == AttackType.DATASET_CORRUPTION:
            manifest = self._resolve_or_create_manifest(request.target_entity_id)
            corrupted_samples: List[SampleRecord] = []
            samples_to_corrupt = max(1, int(len(manifest.samples) * request.intensity)) if manifest.samples else 1

            for i, sample in enumerate(manifest.samples[:samples_to_corrupt]):
                img_path = Path(sample.file_path)
                out_img_path = self.quarantine_dir / f"corrupted_sample_{i}_{img_path.name}"
                self.data_generator.corrupt_samples(image_path=img_path, output_path=out_img_path)
                c_sample = sample.model_copy(deep=True)
                c_sample.file_path = str(out_img_path)
                c_sample.metadata["corrupted"] = True
                corrupted_samples.append(c_sample)

            all_samples = corrupted_samples + manifest.samples[samples_to_corrupt:]
            corrupted_manifest = BatchManifest(
                batch_id=f"{manifest.batch_id}_corrupted",
                dataset_name=manifest.dataset_name,
                format=manifest.format,
                contributor_id=manifest.contributor_id,
                sample_count=len(all_samples),
                merkle_root=manifest.merkle_root,
                samples=all_samples,
            )

            manifest_path = self.quarantine_dir / f"{corrupted_manifest.batch_id}.json"
            with open(manifest_path, "w", encoding="utf-8") as f:
                json.dump(corrupted_manifest.model_dump(mode="json"), f, indent=2)

            attack_sig = canonical_json_hash(corrupted_manifest.model_dump(mode="json"))

            res = AttackExecutionResult(
                attack_id=attack_id,
                attack_type=request.attack_type,
                target_entity_id=request.target_entity_id,
                modified_entity_id=corrupted_manifest.batch_id,
                samples_modified_count=len(corrupted_samples),
                attack_signature=attack_sig,
                description=f"Zero-variance flat blackout frames injected into {len(corrupted_samples)} samples of batch '{manifest.batch_id}'.",
                executed_at=executed_at,
            )
            self.attack_contexts[attack_id] = {
                "manifest": corrupted_manifest,
                "path": manifest_path,
            }
            return res

        elif request.attack_type == AttackType.MODEL_WEIGHT_TAMPERING:
            # Locate or create baseline reference model
            model_info = self._resolve_or_create_model(request.target_entity_id)
            orig_bin = Path(model_info["binary_path"])
            tampered_bin = self.model_generator.tamper_model_weights(orig_bin)

            # Register tampered model to registry to obtain identity manifest
            tampered_manifest = self.model_registry.register_model(
                name=model_info["name"],
                version=f"{model_info['version']}-tampered",
                model_path=tampered_bin,
                format=ModelFormat.GENERIC_BINARY,
                is_reference=False,
            )

            attack_sig = tampered_manifest.binary_sha256

            res = AttackExecutionResult(
                attack_id=attack_id,
                attack_type=request.attack_type,
                target_entity_id=request.target_entity_id,
                modified_entity_id=tampered_manifest.model_id,
                samples_modified_count=1,
                attack_signature=attack_sig,
                description=f"Flipped parameter bytes in model binary '{orig_bin.name}', yielding tampered model '{tampered_manifest.model_id}'.",
                executed_at=executed_at,
            )
            self.attack_contexts[attack_id] = {
                "tampered_model_id": tampered_manifest.model_id,
                "baseline_model_id": model_info["model_id"],
            }
            return res

        elif request.attack_type == AttackType.INFERENCE_TAMPERING:
            record = self._resolve_or_create_inference(request.target_entity_id)
            tampered_record_dict = self.model_generator.tamper_inference_output(
                record=record,
                fake_label=request.target_label or "spoofed_target",
            )
            out_file = self.quarantine_dir / f"{record.record_id}_tampered.json"
            with open(out_file, "w", encoding="utf-8") as f:
                json.dump(tampered_record_dict, f, indent=2)

            attack_sig = tampered_record_dict["output_digest"]

            res = AttackExecutionResult(
                attack_id=attack_id,
                attack_type=request.attack_type,
                target_entity_id=request.target_entity_id,
                modified_entity_id=f"{record.record_id}_tampered",
                samples_modified_count=1,
                attack_signature=attack_sig,
                description=f"Forged post-signature predictions on Inference DNA record '{record.record_id}'.",
                executed_at=executed_at,
            )
            self.attack_contexts[attack_id] = {
                "tampered_record": tampered_record_dict,
                "public_key_pem": self.dna_generator.key_manager.export_public_key_pem(),
            }
            return res

        elif request.attack_type == AttackType.INFERENCE_REPLAY:
            record = self._resolve_or_create_inference(request.target_entity_id)
            res = AttackExecutionResult(
                attack_id=attack_id,
                attack_type=request.attack_type,
                target_entity_id=request.target_entity_id,
                modified_entity_id=f"{record.record_id}_replayed",
                samples_modified_count=1,
                attack_signature=record.nonce,
                description=f"Attempted re-registration with duplicate nonce '{record.nonce}' from record '{record.record_id}'.",
                executed_at=executed_at,
            )
            self.attack_contexts[attack_id] = {
                "original_record": record,
                "replayed_nonce": record.nonce,
            }
            return res

        else:
            raise ValueError(f"Unsupported attack type: {request.attack_type}")

    def verify_detection(self, attack_result: AttackExecutionResult) -> AttackVerificationReport:
        """Audits the executed attack artifact using TRUST-CV defensive engines."""
        ctx = self.attack_contexts.get(attack_result.attack_id, {})
        a_type = attack_result.attack_type

        if a_type in (AttackType.LABEL_FLIPPING, AttackType.BACKDOOR_TRIGGER, AttackType.DATASET_CORRUPTION):
            manifest = ctx.get("manifest")
            if not manifest:
                m_path = self.quarantine_dir / f"{attack_result.modified_entity_id}.json"
                if m_path.is_file():
                    with open(m_path, "r", encoding="utf-8") as f:
                        manifest = BatchManifest(**json.load(f))
                else:
                    raise FileNotFoundError(f"Manifest for {attack_result.modified_entity_id} not found.")

            # Scan with DataIntegrityEngine
            report = self.integrity_engine.scan(manifest)
            finding_types = [f.check_type for f in report.findings]

            if a_type == AttackType.BACKDOOR_TRIGGER:
                detected = IntegrityCheckType.TRIGGER_BACKDOOR in finding_types
                verdict = AssetStatus.QUARANTINED if detected else report.recommendation
                confidence = 0.99 if detected else 0.50
            elif a_type == AttackType.DATASET_CORRUPTION:
                detected = IntegrityCheckType.CORRUPT_OR_OOD in finding_types
                verdict = AssetStatus.QUARANTINED if report.recommendation == AssetStatus.QUARANTINED else AssetStatus.UNDER_REVIEW
                confidence = 0.95 if detected else 0.50
            else:  # LABEL_FLIPPING
                detected = (
                    IntegrityCheckType.LABEL_INCONSISTENCY in finding_types
                    or report.recommendation != AssetStatus.ACCEPTED
                    or len(report.findings) > 0
                )
                verdict = report.recommendation
                confidence = 0.92 if detected else 0.50

            return AttackVerificationReport(
                attack_id=attack_result.attack_id,
                attack_type=a_type,
                detected_by_engine=detected,
                detecting_subsystem="DATA_INTEGRITY",
                assigned_verdict=verdict,
                confidence=confidence,
                details={
                    "total_findings": len(report.findings),
                    "finding_types": [ft.value for ft in finding_types],
                    "health_score": report.overall_health_score,
                },
            )

        elif a_type == AttackType.MODEL_WEIGHT_TAMPERING:
            tampered_id = ctx.get("tampered_model_id") or attack_result.modified_entity_id
            baseline_id = ctx.get("baseline_model_id")

            verify_res = self.model_registry.verify_against_baseline(
                model_id=tampered_id,
                baseline_id=baseline_id,
            )
            detected = not verify_res.is_valid and not verify_res.binary_match
            verdict = AssetStatus.QUARANTINED if detected else AssetStatus.ACCEPTED

            return AttackVerificationReport(
                attack_id=attack_result.attack_id,
                attack_type=a_type,
                detected_by_engine=detected,
                detecting_subsystem="MODEL_IDENTITY",
                assigned_verdict=verdict,
                confidence=1.0 if detected else 0.0,
                details={
                    "binary_match": verify_res.binary_match,
                    "structural_match": verify_res.structural_match,
                    "discrepancies": verify_res.discrepancies,
                },
            )

        elif a_type == AttackType.INFERENCE_TAMPERING:
            tampered_dict = ctx.get("tampered_record")
            pub_key = ctx.get("public_key_pem") or self.dna_generator.key_manager.export_public_key_pem()

            if not tampered_dict:
                rec_file = self.quarantine_dir / f"{attack_result.modified_entity_id}.json"
                if rec_file.is_file():
                    with open(rec_file, "r", encoding="utf-8") as f:
                        tampered_dict = json.load(f)

            tampered_record = InferenceDNARecord(**tampered_dict)
            audit = self.dna_verifier.verify_record(tampered_record, public_key_pem=pub_key)
            detected = not audit.is_valid or not audit.hash_integrity_valid
            verdict = AssetStatus.QUARANTINED if detected else AssetStatus.ACCEPTED

            return AttackVerificationReport(
                attack_id=attack_result.attack_id,
                attack_type=a_type,
                detected_by_engine=detected,
                detecting_subsystem="INFERENCE_DNA",
                assigned_verdict=verdict,
                confidence=1.0 if detected else 0.0,
                details={
                    "hash_integrity_valid": audit.hash_integrity_valid,
                    "signature_valid": audit.signature_valid,
                    "discrepancies": audit.discrepancies,
                },
            )

        elif a_type == AttackType.INFERENCE_REPLAY:
            nonce = ctx.get("replayed_nonce") or attack_result.attack_signature
            detected = False
            error_message = ""

            try:
                # Attempt to register another inference using the duplicate nonce
                self.dna_generator.create_dna_record(
                    model_id="yolo_test",
                    model_identity_digest="0" * 64,
                    input_frame_sha256="1" * 64,
                    prep_spec=PreprocessingSpec(),
                    output=InferenceOutput(predictions=[], raw_output_digest="2" * 64),
                    nonce=nonce,
                )
            except ValueError as exc:
                if "Replay detected" in str(exc):
                    detected = True
                    error_message = str(exc)

            verdict = AssetStatus.QUARANTINED if detected else AssetStatus.ACCEPTED

            return AttackVerificationReport(
                attack_id=attack_result.attack_id,
                attack_type=a_type,
                detected_by_engine=detected,
                detecting_subsystem="INFERENCE_DNA",
                assigned_verdict=verdict,
                confidence=1.0 if detected else 0.0,
                details={"replayed_nonce": nonce, "caught_exception": error_message},
            )

        else:
            raise ValueError(f"Unknown attack type: {a_type}")

    # Helper resolution methods for synthetic or on-disk assets
    def _resolve_or_create_manifest(self, batch_id: str) -> BatchManifest:
        """Finds manifest on disk or generates an isolated synthetic candidate for red-team testing."""
        path = self.manifests_dir / f"{batch_id}.json"
        if path.is_file():
            with open(path, "r", encoding="utf-8") as f:
                return BatchManifest(**json.load(f))

        # Generate synthetic manifest with temporary test images in quarantine
        img_dir = self.quarantine_dir / "synthetic_samples"
        img_dir.mkdir(parents=True, exist_ok=True)
        samples = []

        for i in range(4):
            base_idx = i // 2
            img_path = img_dir / f"{batch_id}_sample_{base_idx}.png"
            if not img_path.is_file():
                arr = np.zeros((64, 64, 3), dtype=np.uint8)
                arr[:, :32] = 200
                arr[:, 32:] = 50
                Image.fromarray(arr).save(img_path)
            samples.append(
                SampleRecord(
                    sample_id=f"samp_{batch_id}_{i}",
                    file_path=str(img_path),
                    sha256_hash=canonical_json_hash({"sample": i, "batch": batch_id}),
                    width=64,
                    height=64,
                    labels=[{"label": "recon_vehicle", "confidence": 0.95}],
                    metadata={"index": i},
                )
            )

        manifest = BatchManifest(
            batch_id=batch_id,
            dataset_name="Synthetic_RedTeam_Set",
            format=DatasetFormat.IMAGE_FOLDER,
            contributor_id="redteam_operator",
            sample_count=len(samples),
            merkle_root="0" * 64,
            samples=samples,
        )
        return manifest

    def _resolve_or_create_model(self, model_id: str) -> Dict[str, Any]:
        """Resolves registered model or creates a reference baseline model binary."""
        existing = self.model_registry.get_model(model_id)
        if existing:
            return {
                "name": existing.name,
                "version": existing.version,
                "model_id": existing.model_id,
                "binary_path": existing.metadata.get("file_path", str(self.quarantine_models_dir / f"{model_id}.bin")),
            }

        # Create dummy baseline binary
        bin_path = self.quarantine_models_dir / f"baseline_{model_id}.bin"
        bin_path.write_bytes(b"ONNX_SYNTHETIC_MODEL_WEIGHTS_FOR_REDTEAM_TESTING_1234567890" * 8)

        baseline_manifest = self.model_registry.register_model(
            name=f"redteam_model_{model_id}",
            version="1.0.0",
            model_path=bin_path,
            format=ModelFormat.GENERIC_BINARY,
            is_reference=True,
        )

        return {
            "name": baseline_manifest.name,
            "version": baseline_manifest.version,
            "model_id": baseline_manifest.model_id,
            "binary_path": bin_path,
        }

    def _resolve_or_create_inference(self, record_id: str) -> InferenceDNARecord:
        """Finds or creates a verifiable Inference DNA record."""
        inf_file = self.data_dir / "inference_dna" / f"{record_id}.json"
        if inf_file.is_file():
            with open(inf_file, "r", encoding="utf-8") as f:
                return InferenceDNARecord(**json.load(f))

        return self.dna_generator.create_dna_record(
            model_id="redteam_target_model",
            model_identity_digest="a" * 64,
            input_frame_sha256="b" * 64,
            prep_spec=PreprocessingSpec(),
            output=InferenceOutput(predictions=[], raw_output_digest="c" * 64),
            record_id=record_id,
        )


# Default singleton instance
default_redteam_lab = RedTeamLab()
