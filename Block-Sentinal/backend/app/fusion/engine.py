"""Evidence Fusion Engine combining cross-layer findings into unified risk verdicts."""
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Dict, List, Optional
import uuid

from app.core.config import settings
from app.crypto.canonical import canonical_json_hash
from app.fusion.correlator import ThreatCorrelator
from app.schemas.base import AssetStatus
from app.schemas.fusion import (
    EvidenceCoverage,
    EvidenceItem,
    EvidenceSource,
    FusedAssessment,
)
from app.schemas.integrity import IntegritySeverity

SOURCE_WEIGHTS: Dict[EvidenceSource, float] = {
    EvidenceSource.INFERENCE_DNA: 0.30,
    EvidenceSource.MODEL_IDENTITY: 0.25,
    EvidenceSource.BEHAVIOURAL_FINGERPRINT: 0.20,
    EvidenceSource.DATA_INTEGRITY: 0.15,
    EvidenceSource.DISTRIBUTION_SHIFT: 0.10,
}

SEVERITY_MULTIPLIERS: Dict[IntegritySeverity, float] = {
    IntegritySeverity.CRITICAL: 1.00,
    IntegritySeverity.HIGH: 0.75,
    IntegritySeverity.MEDIUM: 0.40,
    IntegritySeverity.LOW: 0.15,
}


class EvidenceFusionEngine:
    """Aggregates multi-source assurance evidence, calculates composite risk, and renders verdicts."""

    def __init__(self, storage_dir: Optional[Path] = None):
        base_dir = storage_dir or Path(settings.DATA_DIR) / "fusion"
        self.assessments_dir = base_dir / "assessments"
        self.assessments_dir.mkdir(parents=True, exist_ok=True)

    def fuse(
        self,
        target_entity_id: str,
        evidence: List[EvidenceItem],
    ) -> FusedAssessment:
        """Fuse cross-layer evidence into a unified security assessment and verdict."""
        all_sources = [
            EvidenceSource.DATA_INTEGRITY,
            EvidenceSource.MODEL_IDENTITY,
            EvidenceSource.BEHAVIOURAL_FINGERPRINT,
            EvidenceSource.INFERENCE_DNA,
            EvidenceSource.DISTRIBUTION_SHIFT,
        ]

        # 1. Audit coverage analysis
        sources_checked = sorted(list(set(e.source for e in evidence)), key=lambda s: s.value)
        missing_sources = [s for s in all_sources if s not in sources_checked]
        coverage_ratio = len(sources_checked) / float(len(all_sources)) if all_sources else 0.0

        coverage = EvidenceCoverage(
            sources_checked=sources_checked,
            coverage_ratio=round(coverage_ratio, 2),
            missing_sources=missing_sources,
        )

        # 2. Weighted risk score computation
        raw_weighted_risk = 0.0
        for source, weight in SOURCE_WEIGHTS.items():
            source_items = [e for e in evidence if e.source == source]
            if source_items:
                max_severity_multiplier = max(SEVERITY_MULTIPLIERS[e.severity] for e in source_items)
                raw_weighted_risk += weight * max_severity_multiplier

        # Baseline security threshold guarantees:
        # - Any single CRITICAL item mandates minimum risk of 0.85 (QUARANTINED)
        # - Any HIGH item mandates minimum risk of 0.50 (UNDER_REVIEW)
        # - Any MEDIUM item mandates minimum risk of 0.35 (UNDER_REVIEW)
        # - Purely LOW / clean items remain below 0.30 (ACCEPTED)
        if any(e.severity == IntegritySeverity.CRITICAL for e in evidence):
            raw_weighted_risk = max(raw_weighted_risk, 0.85)
        elif any(e.severity == IntegritySeverity.HIGH for e in evidence):
            raw_weighted_risk = max(raw_weighted_risk, 0.50)
        elif any(e.severity == IntegritySeverity.MEDIUM for e in evidence):
            raw_weighted_risk = max(raw_weighted_risk, 0.35)

        risk_score = round(float(max(0.0, min(1.0, raw_weighted_risk))), 4)

        # 3. Confidence score derived from coverage and evidence sample volume
        volume_factor = min(len(evidence) / 5.0, 1.0)
        confidence_score = round(coverage_ratio * (0.5 + 0.5 * volume_factor), 4)

        # 4. Synthesize multi-source threat narratives
        correlated_findings = ThreatCorrelator.correlate(evidence)

        # 5. Asset status verdict
        if risk_score >= 0.70:
            verdict = AssetStatus.QUARANTINED
        elif risk_score >= 0.30:
            verdict = AssetStatus.UNDER_REVIEW
        else:
            verdict = AssetStatus.ACCEPTED

        # 6. Canonical digest sealing
        assessment_id = f"fused_{uuid.uuid4().hex[:12]}"
        created_at = datetime.now(timezone.utc)

        digest_payload = {
            "assessment_id": assessment_id,
            "target_entity_id": target_entity_id,
            "risk_score": risk_score,
            "confidence_score": confidence_score,
            "verdict": verdict.value,
            "coverage": coverage.model_dump(),
            "correlated_findings": correlated_findings,
            "raw_evidence": [e.model_dump() for e in evidence],
        }
        assessment_digest = canonical_json_hash(digest_payload)

        assessment = FusedAssessment(
            assessment_id=assessment_id,
            target_entity_id=target_entity_id,
            risk_score=risk_score,
            confidence_score=confidence_score,
            verdict=verdict,
            coverage=coverage,
            correlated_findings=correlated_findings,
            raw_evidence=evidence,
            assessment_digest=assessment_digest,
            created_at=created_at,
        )

        # 7. Persist assessment to disk
        out_path = self.assessments_dir / f"{assessment_id}.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(assessment.model_dump(mode="json"), f, indent=2)

        return assessment

    def get_assessment(self, assessment_id: str) -> Optional[FusedAssessment]:
        """Retrieve stored assessment by assessment_id."""
        out_path = self.assessments_dir / f"{assessment_id}.json"
        if not out_path.exists():
            return None
        with open(out_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return FusedAssessment.model_validate(data)


# Default singleton instance
default_fusion_engine = EvidenceFusionEngine()
