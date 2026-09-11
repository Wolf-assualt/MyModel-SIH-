"""Model execution abstraction and behavioural fingerprinting engine."""
import hashlib
import json
import uuid
from pathlib import Path
from typing import Dict, List, Optional
import numpy as np
from PIL import Image

from app.core.config import settings
from app.crypto.canonical import canonical_json_dumps, canonical_json_hash, hash_bytes
from app.fingerprint.battery import TestBatteryGenerator
from app.schemas.base import AssetStatus
from app.schemas.fingerprint import (
    FingerprintComparisonResponse,
    ModelFingerprint,
    PerturbationResult,
    PerturbationType,
)


class ModelExecutor:
    """Provides model inference execution with deterministic surrogate evaluation."""

    def predict(self, model_id: str, image_batch: List[np.ndarray]) -> np.ndarray:
        """Run forward pass returning softmax probabilities of shape (N, 10)."""
        # Deterministic projection matrix seeded by model_id
        model_seed = int(hashlib.sha256(model_id.encode("utf-8")).hexdigest()[:8], 16)
        proj = np.random.default_rng(model_seed).normal(0.0, 1.0, size=(16, 10))

        batch_outputs: List[np.ndarray] = []
        for img in image_batch:
            # Extract 4x4 spatial pooling features
            pil_img = Image.fromarray(img).resize((4, 4)).convert("L")
            feats = np.array(pil_img, dtype=np.float32).flatten() / 255.0
            logits = feats @ proj

            # Softmax
            shifted = logits - np.max(logits)
            exp_l = np.exp(shifted)
            probs = exp_l / np.sum(exp_l)
            batch_outputs.append(probs)

        return np.array(batch_outputs, dtype=np.float32)


class BehaviouralFingerprinter:
    """Runs perturbation battery against models and computes behavioral fingerprints."""

    def __init__(
        self,
        fingerprints_dir: Optional[Path] = None,
        executor: Optional[ModelExecutor] = None,
    ):
        if fingerprints_dir:
            self.fingerprints_dir = Path(fingerprints_dir)
        else:
            self.fingerprints_dir = Path(settings.DATA_DIR) / "fingerprints"

        self.fingerprints_dir.mkdir(parents=True, exist_ok=True)
        self.executor = executor or ModelExecutor()

    def fingerprint_model(
        self,
        model_id: str,
        seed: int = 42,
        count: int = 8,
    ) -> ModelFingerprint:
        """Execute test battery across all perturbation types and generate fingerprint."""
        probe_images = TestBatteryGenerator.generate_probe_images(seed=seed, count=count)
        results: List[PerturbationResult] = []

        for p_type in PerturbationType:
            perturbed = [
                TestBatteryGenerator.apply_perturbation(img, p_type)
                for img in probe_images
            ]
            outputs = self.executor.predict(model_id, perturbed)

            output_digest = hash_bytes(outputs.tobytes())
            mean_conf = float(np.mean(np.max(outputs, axis=1)))
            top_class_id = int(np.argmax(np.mean(outputs, axis=0)))

            results.append(
                PerturbationResult(
                    perturbation=p_type,
                    output_digest=output_digest,
                    mean_confidence=round(mean_conf, 4),
                    top_class_id=top_class_id,
                )
            )

        # Aggregate digest over all perturbation output digests
        aggregate_payload = [r.model_dump(mode="json") for r in results]
        aggregate_digest = canonical_json_hash({"results": aggregate_payload})

        fingerprint = ModelFingerprint(
            fingerprint_id=str(uuid.uuid4()),
            model_id=model_id,
            battery_seed=seed,
            battery_size=count,
            results=results,
            aggregate_digest=aggregate_digest,
        )

        # Persist to disk
        out_file = self.fingerprints_dir / f"{model_id}_{seed}.json"
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(canonical_json_dumps(fingerprint.model_dump(mode="json")))

        return fingerprint

    def load_fingerprint(self, model_id: str, seed: int = 42) -> Optional[ModelFingerprint]:
        """Load an existing model fingerprint from disk."""
        fp_file = self.fingerprints_dir / f"{model_id}_{seed}.json"
        if not fp_file.is_file():
            return None

        with open(fp_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        return ModelFingerprint(**data)

    def compare_fingerprints(
        self,
        candidate_fp: ModelFingerprint,
        reference_fp: ModelFingerprint,
        divergence_threshold: float = 0.95,
    ) -> FingerprintComparisonResponse:
        """Compare candidate behavioral fingerprint against reference baseline."""
        # Check exact aggregate digest match
        if candidate_fp.aggregate_digest == reference_fp.aggregate_digest:
            return FingerprintComparisonResponse(
                candidate_model_id=candidate_fp.model_id,
                reference_model_id=reference_fp.model_id,
                cosine_similarity=1.0,
                mean_squared_error=0.0,
                is_divergent=False,
                status=AssetStatus.ACCEPTED,
                details=[{"perturbation": r.perturbation, "match": True} for r in candidate_fp.results],
            )

        # Build comparison feature vectors
        cand_vec: List[float] = []
        ref_vec: List[float] = []
        details = []

        ref_map = {r.perturbation: r for r in reference_fp.results}

        for cand_res in candidate_fp.results:
            ref_res = ref_map.get(cand_res.perturbation)
            if not ref_res:
                cand_vec.extend([0.0, cand_res.mean_confidence, 0.0])
                ref_vec.extend([1.0, 1.0, 1.0])
                continue

            digest_match = cand_res.output_digest == ref_res.output_digest
            top_class_match = cand_res.top_class_id == ref_res.top_class_id

            cand_vec.extend([
                1.0 if digest_match else 0.0,
                cand_res.mean_confidence,
                1.0 if top_class_match else 0.0,
            ])
            ref_vec.extend([
                1.0,
                ref_res.mean_confidence,
                1.0,
            ])

            details.append({
                "perturbation": cand_res.perturbation.value,
                "digest_match": digest_match,
                "cand_conf": cand_res.mean_confidence,
                "ref_conf": ref_res.mean_confidence,
                "cand_top_class": cand_res.top_class_id,
                "ref_top_class": ref_res.top_class_id,
            })

        u = np.array(cand_vec, dtype=np.float64)
        v = np.array(ref_vec, dtype=np.float64)

        norm_u = np.linalg.norm(u)
        norm_v = np.linalg.norm(v)

        if norm_u == 0 or norm_v == 0:
            cos_sim = 0.0
        else:
            cos_sim = float(np.dot(u, v) / (norm_u * norm_v))

        cos_sim = round(max(0.0, min(1.0, cos_sim)), 4)
        mse = round(float(np.mean((u - v) ** 2)), 4)

        is_divergent = cos_sim < divergence_threshold
        status = AssetStatus.QUARANTINED if is_divergent else AssetStatus.ACCEPTED

        return FingerprintComparisonResponse(
            candidate_model_id=candidate_fp.model_id,
            reference_model_id=reference_fp.model_id,
            cosine_similarity=cos_sim,
            mean_squared_error=mse,
            is_divergent=is_divergent,
            status=status,
            details=details,
        )


default_fingerprinter = BehaviouralFingerprinter()
