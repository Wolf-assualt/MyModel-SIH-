"""Detectors for exact duplicates, near duplicates, label inconsistency, quality/OOD, and backdoors."""
import uuid
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional
import numpy as np
from PIL import Image

from app.crypto.canonical import hash_bytes
from app.integrity.hasher import compute_dhash, hamming_distance
from app.schemas.dataset import SampleRecord
from app.schemas.integrity import (
    IntegrityCheckType,
    IntegrityFinding,
    IntegritySeverity,
)


class DuplicateDetector:
    """Detects exact byte-level duplicates (SHA-256) and perceptual near-duplicates (dHash)."""

    def detect(
        self,
        samples: List[SampleRecord],
        duplicate_threshold: int = 4,
    ) -> List[IntegrityFinding]:
        findings: List[IntegrityFinding] = []

        # 1. Exact Duplicate Detection via SHA-256
        sha_groups: Dict[str, List[SampleRecord]] = defaultdict(list)
        for s in samples:
            sha_groups[s.sha256_hash].append(s)

        exact_duplicate_sample_ids = set()
        for sha, group in sha_groups.items():
            if len(group) > 1:
                ids = [s.sample_id for s in group]
                exact_duplicate_sample_ids.update(ids)
                findings.append(
                    IntegrityFinding(
                        finding_id=str(uuid.uuid4()),
                        check_type=IntegrityCheckType.EXACT_DUPLICATE,
                        severity=IntegritySeverity.MEDIUM,
                        sample_ids=ids,
                        description=f"Identified {len(group)} exact byte-level duplicate samples with identical SHA-256 digest ({sha[:16]}...).",
                        metric_score=0.0,
                        details={"sha256": sha, "duplicate_count": len(group)},
                    )
                )

        # 2. Near-Duplicate Detection via dHash
        # Precompute dHash for samples
        sample_hashes: List[tuple[SampleRecord, Optional[str]]] = []
        for s in samples:
            try:
                dh = compute_dhash(Path(s.file_path))
                sample_hashes.append((s, dh))
            except Exception:
                sample_hashes.append((s, None))

        n = len(sample_hashes)
        for i in range(n):
            s_i, h_i = sample_hashes[i]
            if not h_i:
                continue

            for j in range(i + 1, n):
                s_j, h_j = sample_hashes[j]
                if not h_j:
                    continue

                # Skip if already flagged as exact duplicate pair
                if s_i.sha256_hash == s_j.sha256_hash:
                    continue

                dist = hamming_distance(h_i, h_j)
                if dist <= duplicate_threshold:
                    findings.append(
                        IntegrityFinding(
                            finding_id=str(uuid.uuid4()),
                            check_type=IntegrityCheckType.NEAR_DUPLICATE,
                            severity=IntegritySeverity.LOW,
                            sample_ids=[s_i.sample_id, s_j.sample_id],
                            description=f"Perceptual near-duplicate image pair detected (Hamming distance {dist} <= {duplicate_threshold}).",
                            metric_score=float(dist),
                            details={
                                "sample_a": s_i.sample_id,
                                "sample_b": s_j.sample_id,
                                "hamming_distance": dist,
                                "threshold": duplicate_threshold,
                            },
                        )
                    )

        return findings


class LabelInconsistencyDetector:
    """Detects near-duplicate or identical images that have conflicting label annotations."""

    def detect(
        self,
        samples: List[SampleRecord],
        distance_threshold: int = 3,
    ) -> List[IntegrityFinding]:
        findings: List[IntegrityFinding] = []

        sample_hashes: List[tuple[SampleRecord, Optional[str]]] = []
        for s in samples:
            try:
                dh = compute_dhash(Path(s.file_path))
                sample_hashes.append((s, dh))
            except Exception:
                sample_hashes.append((s, None))

        n = len(sample_hashes)
        for i in range(n):
            s_i, h_i = sample_hashes[i]
            if not h_i or not s_i.labels:
                continue

            for j in range(i + 1, n):
                s_j, h_j = sample_hashes[j]
                if not h_j or not s_j.labels:
                    continue

                dist = hamming_distance(h_i, h_j)
                if dist <= distance_threshold:
                    # Check if labels conflict
                    if s_i.labels != s_j.labels:
                        findings.append(
                            IntegrityFinding(
                                finding_id=str(uuid.uuid4()),
                                check_type=IntegrityCheckType.LABEL_INCONSISTENCY,
                                severity=IntegritySeverity.HIGH,
                                sample_ids=[s_i.sample_id, s_j.sample_id],
                                description=f"Conflicting label annotations assigned to near-identical images (Hamming distance {dist}).",
                                metric_score=float(dist),
                                details={
                                    "sample_a": s_i.sample_id,
                                    "labels_a": s_i.labels,
                                    "sample_b": s_j.sample_id,
                                    "labels_b": s_j.labels,
                                    "distance": dist,
                                },
                            )
                        )

        return findings


class QualityAndOODDetector:
    """Detects solid/zero-variance images, corrupt files, or extreme aspect ratio anomalies."""

    def detect(self, samples: List[SampleRecord]) -> List[IntegrityFinding]:
        findings: List[IntegrityFinding] = []

        for s in samples:
            img_path = Path(s.file_path)
            if not img_path.is_file():
                findings.append(
                    IntegrityFinding(
                        finding_id=str(uuid.uuid4()),
                        check_type=IntegrityCheckType.CORRUPT_OR_OOD,
                        severity=IntegritySeverity.CRITICAL,
                        sample_ids=[s.sample_id],
                        description=f"Image file missing or unreadable on disk: {img_path}",
                        metric_score=0.0,
                        details={"file_path": str(img_path)},
                    )
                )
                continue

            try:
                with Image.open(img_path) as img:
                    width, height = img.size
                    # Check extreme aspect ratio
                    aspect_ratio = width / height if height > 0 else 0
                    if aspect_ratio > 20.0 or aspect_ratio < 0.05:
                        findings.append(
                            IntegrityFinding(
                                finding_id=str(uuid.uuid4()),
                                check_type=IntegrityCheckType.CORRUPT_OR_OOD,
                                severity=IntegritySeverity.MEDIUM,
                                sample_ids=[s.sample_id],
                                description=f"Extreme aspect ratio anomaly detected: {aspect_ratio:.2f}",
                                metric_score=float(aspect_ratio),
                                details={"width": width, "height": height, "aspect_ratio": aspect_ratio},
                            )
                        )

                    # Check zero/near-zero variance (solid black/white/blank)
                    gray = img.convert("L")
                    arr = np.array(gray, dtype=np.float32)
                    var = float(np.var(arr))

                    if var < 1.0:
                        findings.append(
                            IntegrityFinding(
                                finding_id=str(uuid.uuid4()),
                                check_type=IntegrityCheckType.CORRUPT_OR_OOD,
                                severity=IntegritySeverity.HIGH,
                                sample_ids=[s.sample_id],
                                description=f"Zero-variance flat image detected (variance: {var:.4f}). Image appears to be solid color or sensor blackout.",
                                metric_score=var,
                                details={"variance": var, "dimensions": [width, height]},
                            )
                        )

            except Exception as exc:
                findings.append(
                    IntegrityFinding(
                        finding_id=str(uuid.uuid4()),
                        check_type=IntegrityCheckType.CORRUPT_OR_OOD,
                        severity=IntegritySeverity.HIGH,
                        sample_ids=[s.sample_id],
                        description=f"Corrupt or invalid image payload: {str(exc)}",
                        metric_score=0.0,
                        details={"error": str(exc)},
                    )
                )

        return findings


class TriggerBackdoorDetector:
    """Detects recurring static patch patterns in corner regions across samples with identical target label."""

    def detect(self, samples: List[SampleRecord], patch_size: int = 16) -> List[IntegrityFinding]:
        findings: List[IntegrityFinding] = []
        if len(samples) < 2:
            return self._detect_isolated_trigger(samples, patch_size)

        findings.extend(self._detect_isolated_trigger(samples, patch_size))

        # Group samples by primary label class
        label_groups: Dict[str, List[SampleRecord]] = defaultdict(list)
        for s in samples:
            label_key = str(s.labels) if s.labels else "unlabeled"
            label_groups[label_key].append(s)

        corner_names = ["top_left", "top_right", "bottom_left", "bottom_right"]

        for label_key, group in label_groups.items():
            if len(group) < 2:
                continue

            # Check each corner for identical static high-contrast patch signatures
            for c_name in corner_names:
                patch_signatures: Dict[str, List[str]] = defaultdict(list)

                for sample in group:
                    try:
                        with Image.open(sample.file_path) as img:
                            w, h = img.size
                            if w < patch_size or h < patch_size:
                                continue

                            if c_name == "top_left":
                                box = (0, 0, patch_size, patch_size)
                            elif c_name == "top_right":
                                box = (w - patch_size, 0, w, patch_size)
                            elif c_name == "bottom_left":
                                box = (0, h - patch_size, patch_size, h)
                            else:  # bottom_right
                                box = (w - patch_size, h - patch_size, w, h)

                            patch = img.crop(box).convert("L")
                            arr = np.array(patch, dtype=np.uint8)

                            # Only consider patches with noticeable contrast/structure
                            if float(np.var(arr)) > 25.0:
                                sig = hash_bytes(arr.tobytes())
                                patch_signatures[sig].append(sample.sample_id)
                    except Exception:
                        continue

                for sig, sample_ids in patch_signatures.items():
                    if len(sample_ids) >= 2:
                        findings.append(
                            IntegrityFinding(
                                finding_id=str(uuid.uuid4()),
                                check_type=IntegrityCheckType.TRIGGER_BACKDOOR,
                                severity=IntegritySeverity.CRITICAL,
                                sample_ids=sample_ids,
                                description=f"Suspicious repeated static localized patch pattern detected in {c_name} corner across multiple samples sharing label '{label_key}'.",
                                metric_score=float(len(sample_ids)),
                                details={
                                    "corner": c_name,
                                    "patch_size": patch_size,
                                    "matched_samples": sample_ids,
                                    "target_label": label_key,
                                    "patch_signature": sig[:16],
                                },
                            )
                        )

        return findings

    def _detect_isolated_trigger(
        self,
        samples: List[SampleRecord],
        patch_size: int,
    ) -> List[IntegrityFinding]:
        """Detect a measured high-contrast trigger patch when no comparison sample exists."""
        findings: List[IntegrityFinding] = []
        corner_names = ["top_left", "top_right", "bottom_left", "bottom_right"]
        for sample in samples:
            try:
                with Image.open(sample.file_path) as img:
                    width, height = img.size
                    if width < patch_size or height < patch_size:
                        continue
                    for corner in corner_names:
                        if corner == "top_left":
                            box = (0, 0, patch_size, patch_size)
                        elif corner == "top_right":
                            box = (width - patch_size, 0, width, patch_size)
                        elif corner == "bottom_left":
                            box = (0, height - patch_size, patch_size, height)
                        else:
                            box = (width - patch_size, height - patch_size, width, height)

                        patch = np.array(img.crop(box).convert("L"), dtype=np.float32)
                        variance = float(np.var(patch))
                        dark_ratio = float(np.mean(patch < 32))
                        light_ratio = float(np.mean(patch > 224))
                        if variance >= 5000.0 and dark_ratio >= 0.20 and light_ratio >= 0.20:
                            findings.append(
                                IntegrityFinding(
                                    finding_id=str(uuid.uuid4()),
                                    check_type=IntegrityCheckType.TRIGGER_BACKDOOR,
                                    severity=IntegritySeverity.CRITICAL,
                                    sample_ids=[sample.sample_id],
                                    description=(
                                        f"High-contrast localized trigger candidate detected in {corner} corner "
                                        f"(variance {variance:.1f}, dark ratio {dark_ratio:.2f}, light ratio {light_ratio:.2f})."
                                    ),
                                    metric_score=min(1.0, variance / 16384.0),
                                    details={
                                        "corner": corner,
                                        "patch_size": patch_size,
                                        "variance": variance,
                                        "dark_ratio": dark_ratio,
                                        "light_ratio": light_ratio,
                                        "isolated_sample": True,
                                    },
                                )
                            )
                            break
            except Exception:
                continue
        return findings
