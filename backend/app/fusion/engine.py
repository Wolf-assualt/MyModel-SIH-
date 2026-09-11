"""Evidence Fusion Engine combining cross-layer findings into explainable assurance decisions."""
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
import uuid

from app.core.config import settings
from app.crypto.canonical import canonical_json_dumps, canonical_json_hash
from app.crypto.signer import KeyManager, default_key_manager
from app.fusion.correlator import ThreatCorrelator
from app.schemas.base import AssetStatus
from app.schemas.fusion import (
    AssuranceAction,
    AssuranceRiskLevel,
    EvidenceCoverage,
    EvidenceItem,
    EvidenceSource,
    EvidenceSourceDomain,
    FusedAssessment,
    QuarantineRecord,
)
from app.schemas.integrity import IntegritySeverity

# Explicit configurable reliability weights per assurance domain
SOURCE_WEIGHTS: Dict[EvidenceSource, float] = {
    EvidenceSource.INFERENCE_DNA: 1.00,
    EvidenceSource.MODEL_IDENTITY: 1.00,
    EvidenceSource.CRYPTO_VERIFICATION: 1.00,
    EvidenceSource.SYSTEM_INTEGRITY: 0.90,
    EvidenceSource.BEHAVIOURAL_FINGERPRINT: 0.85,
    EvidenceSource.DATA_INTEGRITY: 0.85,
    EvidenceSource.DISTRIBUTION_SHIFT: 0.60,
}

# Domain-to-EvidenceSource mapping
DOMAIN_TO_SOURCE: Dict[EvidenceSourceDomain, EvidenceSource] = {
    EvidenceSourceDomain.DATASET: EvidenceSource.DATA_INTEGRITY,
    EvidenceSourceDomain.MODEL: EvidenceSource.MODEL_IDENTITY,
    EvidenceSourceDomain.BEHAVIOR: EvidenceSource.BEHAVIOURAL_FINGERPRINT,
    EvidenceSourceDomain.INFERENCE: EvidenceSource.INFERENCE_DNA,
    EvidenceSourceDomain.DRIFT: EvidenceSource.DISTRIBUTION_SHIFT,
    EvidenceSourceDomain.CRYPTO: EvidenceSource.CRYPTO_VERIFICATION,
    EvidenceSourceDomain.SYSTEM: EvidenceSource.SYSTEM_INTEGRITY,
}

SEVERITY_MULTIPLIERS: Dict[IntegritySeverity, float] = {
    IntegritySeverity.CRITICAL: 1.00,
    IntegritySeverity.HIGH: 0.70,
    IntegritySeverity.MEDIUM: 0.35,
    IntegritySeverity.LOW: 0.10,
}


class EvidenceFusionEngine:
    """Aggregates multi-source assurance evidence, applies hard-vetos, and renders explainable decisions."""

    def __init__(
        self,
        storage_dir: Optional[Path] = None,
        key_manager: Optional[KeyManager] = None,
    ):
        base_dir = storage_dir or Path(settings.DATA_DIR) / "fusion"
        self.assessments_dir = base_dir / "assessments"
        self.evidence_dir = base_dir / "evidence"
        self.quarantines_dir = base_dir / "quarantines"
        self.assessments_dir.mkdir(parents=True, exist_ok=True)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.quarantines_dir.mkdir(parents=True, exist_ok=True)
        self.key_manager = key_manager or default_key_manager

    # -------------------------------------------------------------------------
    # Evidence Persistence & Retrieval
    # -------------------------------------------------------------------------

    def register_evidence(self, item: EvidenceItem) -> EvidenceItem:
        """Persist a single verified EvidenceItem to storage."""
        if not item.evidence_id:
            item.evidence_id = f"ev_{uuid.uuid4().hex[:12]}"

        # Sync source and source_domain
        if item.source_domain and not item.source:
            item.source = DOMAIN_TO_SOURCE.get(item.source_domain, EvidenceSource.DATA_INTEGRITY)

        out_path = self.evidence_dir / f"{item.evidence_id}.json"
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(canonical_json_dumps(item.model_dump(mode="json")))

        return item

    def get_evidence(self, evidence_id: str) -> Optional[EvidenceItem]:
        """Retrieve stored EvidenceItem by evidence_id."""
        path = self.evidence_dir / f"{evidence_id}.json"
        if not path.is_file():
            return None
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return EvidenceItem.model_validate(data)

    def list_evidence(self) -> List[EvidenceItem]:
        """List all stored EvidenceItems."""
        items: List[EvidenceItem] = []
        for p in self.evidence_dir.glob("*.json"):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = json.load(f)
                items.append(EvidenceItem.model_validate(data))
            except Exception:
                continue
        return items

    # -------------------------------------------------------------------------
    # Quarantine Management
    # -------------------------------------------------------------------------

    def quarantine_entity(
        self,
        subject_id: str,
        reason: str,
        evidence_ids: Optional[List[str]] = None,
        subject_type: str = "MODEL",
    ) -> QuarantineRecord:
        """Place an asset into active quarantine and record audit record."""
        quarantine_id = f"quarantine_{uuid.uuid4().hex[:12]}"
        rec = QuarantineRecord(
            quarantine_id=quarantine_id,
            subject_id=subject_id,
            subject_type=subject_type,
            reason=reason,
            evidence_ids=evidence_ids or [],
            is_active=True,
            created_at=datetime.now(timezone.utc),
        )
        path = self.quarantines_dir / f"{quarantine_id}.json"
        with open(path, "w", encoding="utf-8") as f:
            f.write(canonical_json_dumps(rec.model_dump(mode="json")))
        return rec

    def get_quarantine(self, quarantine_id: str) -> Optional[QuarantineRecord]:
        """Retrieve a specific QuarantineRecord."""
        path = self.quarantines_dir / f"{quarantine_id}.json"
        if not path.is_file():
            return None
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return QuarantineRecord.model_validate(data)

    def list_quarantines(self, active_only: bool = False) -> List[QuarantineRecord]:
        """List all quarantine records."""
        records: List[QuarantineRecord] = []
        for p in self.quarantines_dir.glob("*.json"):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = json.load(f)
                rec = QuarantineRecord.model_validate(data)
                if not active_only or rec.is_active:
                    records.append(rec)
            except Exception:
                continue
        return records

    def resolve_quarantine(
        self,
        quarantine_id: str,
        resolved_by: str,
        resolution_notes: str,
    ) -> QuarantineRecord:
        """Explicitly resolve and clear an active quarantine record with forensic notes."""
        rec = self.get_quarantine(quarantine_id)
        if not rec:
            raise FileNotFoundError(f"Quarantine record '{quarantine_id}' not found.")

        rec.is_active = False
        rec.resolved_at = datetime.now(timezone.utc)
        rec.resolved_by = resolved_by
        rec.resolution_notes = resolution_notes

        path = self.quarantines_dir / f"{quarantine_id}.json"
        with open(path, "w", encoding="utf-8") as f:
            f.write(canonical_json_dumps(rec.model_dump(mode="json")))

        return rec

    # -------------------------------------------------------------------------
    # Evidence Fusion Engine Core
    # -------------------------------------------------------------------------

    def fuse(
        self,
        target_entity_id: str,
        evidence: List[EvidenceItem],
        strict_subject_binding: bool = True,
    ) -> FusedAssessment:
        """Fuse multi-source evidence into an explainable assurance decision and durable record."""
        # 1. Subject & Identity Binding Check
        if strict_subject_binding and evidence:
            distinct_models: Set[str] = set()
            distinct_datasets: Set[str] = set()
            for e in evidence:
                if e.related_model_id:
                    distinct_models.add(e.related_model_id)
                if e.related_dataset_id:
                    distinct_datasets.add(e.related_dataset_id)

            if len(distinct_models) > 1:
                m_list = list(distinct_models)
                raise ValueError(
                    f"Evidence subject mismatch: conflicting related_model_ids '{m_list[0]}' and '{m_list[1]}' "
                    f"cannot be fused for the same target entity '{target_entity_id}'."
                )

            if len(distinct_datasets) > 1:
                d_list = list(distinct_datasets)
                raise ValueError(
                    f"Evidence subject mismatch: conflicting related_dataset_ids '{d_list[0]}' and '{d_list[1]}' "
                    f"cannot be fused for the same target entity '{target_entity_id}'."
                )

        all_standard_sources = [
            EvidenceSource.DATA_INTEGRITY,
            EvidenceSource.MODEL_IDENTITY,
            EvidenceSource.BEHAVIOURAL_FINGERPRINT,
            EvidenceSource.INFERENCE_DNA,
            EvidenceSource.DISTRIBUTION_SHIFT,
        ]

        # 2. Audit coverage analysis
        sources_checked = sorted(list(set(e.source for e in evidence)), key=lambda s: s.value)
        missing_sources = [s for s in all_standard_sources if s not in sources_checked]
        coverage_ratio = len(sources_checked) / float(len(all_standard_sources)) if all_standard_sources else 0.0

        coverage = EvidenceCoverage(
            sources_checked=sources_checked,
            coverage_ratio=round(coverage_ratio, 2),
            missing_sources=missing_sources,
        )

        # 3. Hard Quarantine Veto Evaluation
        hard_veto_triggered = False
        veto_reasons: List[str] = []
        decisive_evidence: List[str] = []

        for e in evidence:
            desc_lower = e.description.lower()
            # Cryptographic signature failures
            if e.severity == IntegritySeverity.CRITICAL and (
                "signature" in desc_lower or "forger" in desc_lower or e.source == EvidenceSource.CRYPTO_VERIFICATION
            ):
                hard_veto_triggered = True
                msg = f"Hard Veto Triggered: Invalid or forged cryptographic signature ({e.description})"
                veto_reasons.append(msg)
                decisive_evidence.append(e.evidence_id)

            # Provenance & Replay attacks
            elif e.severity == IntegritySeverity.CRITICAL and (
                "replay" in desc_lower or "continuity" in desc_lower or "provenance" in desc_lower or e.source == EvidenceSource.INFERENCE_DNA
            ):
                hard_veto_triggered = True
                msg = f"Hard Veto Triggered: Inference provenance chain compromise or replay attack ({e.description})"
                veto_reasons.append(msg)
                decisive_evidence.append(e.evidence_id)

            # Model weights / structural substitution
            elif e.severity == IntegritySeverity.CRITICAL and (
                "mismatch" in desc_lower or "substitution" in desc_lower or "weight" in desc_lower or e.source == EvidenceSource.MODEL_IDENTITY
            ):
                hard_veto_triggered = True
                msg = f"Hard Veto Triggered: Model identity or weight verification failure ({e.description})"
                veto_reasons.append(msg)
                decisive_evidence.append(e.evidence_id)

            # Confirmed critical dataset backdoor/poisoning
            elif e.severity == IntegritySeverity.CRITICAL and (
                "backdoor" in desc_lower or "poison" in desc_lower or e.source == EvidenceSource.DATA_INTEGRITY
            ):
                hard_veto_triggered = True
                msg = f"Hard Veto Triggered: Critical dataset poisoning or backdoor trigger ({e.description})"
                veto_reasons.append(msg)
                decisive_evidence.append(e.evidence_id)

        # 4. Reliability-Weighted Evidence Aggregation
        contributing_evidence: List[Dict[str, Any]] = []
        raw_weighted_risk = 0.0
        total_weight = 0.0

        for source, weight in SOURCE_WEIGHTS.items():
            source_items = [e for e in evidence if e.source == source]
            if source_items:
                max_sev = max(source_items, key=lambda x: SEVERITY_MULTIPLIERS[x.severity])
                sev_mult = SEVERITY_MULTIPLIERS[max_sev.severity]
                # Modulate by item confidence/reliability if provided
                conf = max_sev.confidence if max_sev.confidence > 0 else 1.0
                effective_weight = weight * conf
                weighted_contribution = effective_weight * sev_mult
                raw_weighted_risk += weighted_contribution
                total_weight += effective_weight

                contributing_evidence.append({
                    "source": source.value,
                    "evidence_id": max_sev.evidence_id,
                    "severity": max_sev.severity.value,
                    "reliability_weight": weight,
                    "confidence": conf,
                    "weighted_risk_contribution": round(weighted_contribution, 4),
                    "description": max_sev.description,
                })

        normalized_risk = (raw_weighted_risk / total_weight) if total_weight > 0 else 0.0

        # High / Critical severity guarantees
        if any(e.severity == IntegritySeverity.CRITICAL for e in evidence):
            normalized_risk = max(normalized_risk, 0.85)
        elif any(e.severity == IntegritySeverity.HIGH for e in evidence):
            normalized_risk = max(normalized_risk, 0.50)
        elif any(e.severity == IntegritySeverity.MEDIUM for e in evidence):
            normalized_risk = max(normalized_risk, 0.35)

        # 5. Drift Isolation Rule:
        # If ONLY distribution shift exists (no other layer compromised), drift alone must NOT trigger quarantine
        non_drift_items = [e for e in evidence if e.source != EvidenceSource.DISTRIBUTION_SHIFT and e.severity in [IntegritySeverity.MEDIUM, IntegritySeverity.HIGH, IntegritySeverity.CRITICAL]]
        if not non_drift_items and not hard_veto_triggered:
            # Bounded to maximum REVIEW risk level
            normalized_risk = min(normalized_risk, 0.45)

        # 6. Apply Hard Veto Precedence
        if hard_veto_triggered:
            risk_score = 1.0
            risk_level = AssuranceRiskLevel.CRITICAL
            verdict = AssetStatus.QUARANTINED
            action = AssuranceAction.BLOCK
            # Automatically record quarantine
            self.quarantine_entity(
                subject_id=target_entity_id,
                reason="; ".join(veto_reasons),
                evidence_ids=decisive_evidence,
                subject_type="PIPELINE_RUN",
            )
        else:
            risk_score = round(float(max(0.0, min(1.0, normalized_risk))), 4)
            if risk_score >= 0.70:
                risk_level = AssuranceRiskLevel.CRITICAL
                verdict = AssetStatus.QUARANTINED
                action = AssuranceAction.BLOCK
            elif risk_score >= 0.50:
                risk_level = AssuranceRiskLevel.HIGH
                verdict = AssetStatus.UNDER_REVIEW
                action = AssuranceAction.REVIEW
            elif risk_score >= 0.25:
                risk_level = AssuranceRiskLevel.MEDIUM
                verdict = AssetStatus.UNDER_REVIEW
                action = AssuranceAction.REVIEW
            else:
                risk_level = AssuranceRiskLevel.LOW
                verdict = AssetStatus.ACCEPTED
                action = AssuranceAction.ALLOW

        # 7. Confidence Score
        volume_factor = min(len(evidence) / 5.0, 1.0)
        confidence_score = round(coverage_ratio * (0.5 + 0.5 * volume_factor), 4) if evidence else 0.0

        # 8. Synthesize Correlated Findings
        correlated_findings = ThreatCorrelator.correlate(evidence)

        # 9. Formulate Transparent Forensic Explanation
        if hard_veto_triggered:
            explanation = (
                f"Assurance Action: BLOCK (QUARANTINED). Hard cryptographic/integrity veto condition triggered. "
                f"Veto Reasons: {'; '.join(veto_reasons)}."
            )
        elif verdict == AssetStatus.ACCEPTED:
            explanation = (
                f"Assurance Action: ALLOW (ACCEPTED). All evaluated evidence sources (coverage: {coverage.coverage_ratio * 100:.0f}%) "
                f"fall within verified operational baseline thresholds (Risk Score: {risk_score:.4f})."
            )
        else:
            explanation = (
                f"Assurance Action: REVIEW (UNDER_REVIEW). Elevated risk ({risk_score:.4f}) detected. "
                f"Contributing factors: {len(contributing_evidence)} active signals. Corroborations: {len(correlated_findings)}."
            )

        # 10. Seal Fused Assessment Digest
        assessment_id = f"fused_{uuid.uuid4().hex[:12]}"
        created_at = datetime.now(timezone.utc)

        digest_payload = {
            "assessment_id": assessment_id,
            "target_entity_id": target_entity_id,
            "risk_score": risk_score,
            "risk_level": risk_level.value,
            "confidence_score": confidence_score,
            "verdict": verdict.value,
            "action": action.value,
            "hard_veto_triggered": hard_veto_triggered,
            "veto_reasons": veto_reasons,
            "coverage": coverage.model_dump(),
            "correlated_findings": correlated_findings,
            "raw_evidence": [e.model_dump() for e in evidence],
        }
        assessment_digest = canonical_json_hash(digest_payload)
        signature = self.key_manager.sign_hash(assessment_digest)

        assessment = FusedAssessment(
            assessment_id=assessment_id,
            target_entity_id=target_entity_id,
            risk_score=risk_score,
            risk_level=risk_level,
            confidence_score=confidence_score,
            verdict=verdict,
            action=action,
            hard_veto_triggered=hard_veto_triggered,
            veto_reasons=veto_reasons,
            coverage=coverage,
            correlated_findings=correlated_findings,
            contributing_evidence=contributing_evidence,
            decisive_evidence=decisive_evidence,
            raw_evidence=evidence,
            explanation=explanation,
            assessment_digest=assessment_digest,
            signature=signature,
            created_at=created_at,
            provenance_references=[e.evidence_id for e in evidence],
        )

        # 11. Persist Assessment to Disk
        out_path = self.assessments_dir / f"{assessment_id}.json"
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(canonical_json_dumps(assessment.model_dump(mode="json")))

        return assessment

    def get_assessment(self, assessment_id: str) -> Optional[FusedAssessment]:
        """Retrieve stored assessment by assessment_id."""
        out_path = self.assessments_dir / f"{assessment_id}.json"
        if not out_path.is_file():
            return None
        with open(out_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return FusedAssessment.model_validate(data)

    def list_assessments(self) -> List[FusedAssessment]:
        """List all stored fused assessments."""
        assessments: List[FusedAssessment] = []
        for p in self.assessments_dir.glob("*.json"):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = json.load(f)
                assessments.append(FusedAssessment.model_validate(data))
            except Exception:
                continue
        return assessments


# Default singleton instance
default_fusion_engine = EvidenceFusionEngine()
