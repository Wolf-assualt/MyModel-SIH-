"""Evidence Fusion Engine combining cross-layer findings into authoritative risk verdicts."""
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Dict, List, Optional, Set
import uuid

from app.core.config import settings
from app.crypto.canonical import canonical_json_hash
from app.crypto.signer import KeyManager
from app.fusion.correlator import ThreatCorrelator
from app.schemas.base import AssetStatus
from app.schemas.fusion import (
    AssuranceAction,
    AssuranceRiskLevel,
    EvidenceCoverage,
    EvidenceItem,
    EvidenceSource,
    FusedAssessment,
    QuarantineRecord,
)
from app.schemas.integrity import IntegritySeverity

SOURCE_WEIGHTS: Dict[EvidenceSource, float] = {
    EvidenceSource.CRYPTO_VERIFICATION: 0.35,
    EvidenceSource.INFERENCE_DNA: 0.25,
    EvidenceSource.MODEL_IDENTITY: 0.20,
    EvidenceSource.BEHAVIOURAL_FINGERPRINT: 0.15,
    EvidenceSource.DATA_INTEGRITY: 0.15,
    EvidenceSource.CONTRIBUTOR_RISK: 0.10,
    EvidenceSource.DISTRIBUTION_SHIFT: 0.10,
}

SEVERITY_MULTIPLIERS: Dict[IntegritySeverity, float] = {
    IntegritySeverity.CRITICAL: 1.00,
    IntegritySeverity.HIGH: 0.75,
    IntegritySeverity.MEDIUM: 0.40,
    IntegritySeverity.LOW: 0.15,
}


class EvidenceFusionEngine:
    """Aggregates multi-source assurance evidence, calculates composite risk, and renders authoritative verdicts."""

    def __init__(self, storage_dir: Optional[Path] = None, key_manager: Optional[KeyManager] = None):
        base_dir = storage_dir or Path(settings.DATA_DIR) / "fusion"
        self.storage_dir = base_dir
        self.assessments_dir = self.storage_dir / "assessments"
        self.evidence_dir = self.storage_dir / "evidence"
        self.quarantine_dir = self.storage_dir / "quarantine"

        self.assessments_dir.mkdir(parents=True, exist_ok=True)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)

        self.key_manager = key_manager or KeyManager()
        self._evidence_cache: Dict[str, EvidenceItem] = {}
        self._quarantine_cache: Dict[str, QuarantineRecord] = {}
        self._load_caches()

    def _load_caches(self) -> None:
        for p in self.evidence_dir.glob("*.json"):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    item = EvidenceItem.model_validate(data)
                    self._evidence_cache[item.evidence_id] = item
            except Exception:
                continue

        for p in self.quarantine_dir.glob("*.json"):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    rec = QuarantineRecord.model_validate(data)
                    self._quarantine_cache[rec.quarantine_id] = rec
            except Exception:
                continue

    # =========================================================================
    # Evidence Item Store
    # =========================================================================

    def register_evidence(self, item: EvidenceItem) -> EvidenceItem:
        """Register an individual verified EvidenceItem into the central assurance store."""
        if not item.evidence_id or not item.evidence_id.strip():
            raise ValueError("Evidence item must have a valid non-empty evidence_id.")

        if not item.evidence_digest:
            payload = {
                "evidence_id": item.evidence_id,
                "source": item.source.value,
                "severity": item.severity.value,
                "metric_value": item.metric_value,
                "description": item.description,
                "subject_id": item.subject_id,
                "metadata": item.metadata,
            }
            item.evidence_digest = canonical_json_hash(payload)

        self._evidence_cache[item.evidence_id] = item
        out_path = self.evidence_dir / f"{item.evidence_id}.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(item.model_dump(mode="json"), f, indent=2)

        return item

    def get_evidence(self, evidence_id: str) -> Optional[EvidenceItem]:
        """Retrieve stored evidence item by ID."""
        if evidence_id in self._evidence_cache:
            return self._evidence_cache[evidence_id]
        out_path = self.evidence_dir / f"{evidence_id}.json"
        if not out_path.exists():
            return None
        with open(out_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        item = EvidenceItem.model_validate(data)
        self._evidence_cache[item.evidence_id] = item
        return item

    def list_evidence(self) -> List[EvidenceItem]:
        """List all stored evidence items sorted by evidence_id."""
        return sorted(list(self._evidence_cache.values()), key=lambda e: e.evidence_id)

    # =========================================================================
    # Quarantine Management
    # =========================================================================

    def quarantine_entity(
        self,
        subject_id: str,
        reason: str,
        evidence_ids: Optional[List[str]] = None,
        subject_type: str = "ASSET",
    ) -> QuarantineRecord:
        """Place an asset or entity into quarantine with cryptographic audit tracking."""
        quarantine_id = f"quar_{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc)
        record = QuarantineRecord(
            quarantine_id=quarantine_id,
            subject_id=subject_id,
            subject_type=subject_type,
            reason=reason,
            evidence_ids=evidence_ids or [],
            is_active=True,
            quarantined_at=now,
            created_at=now,
        )
        self._quarantine_cache[quarantine_id] = record
        out_path = self.quarantine_dir / f"{quarantine_id}.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(record.model_dump(mode="json"), f, indent=2)

        return record

    def list_quarantines(self, active_only: bool = True) -> List[QuarantineRecord]:
        """List quarantine records, optionally filtering to active quarantines only."""
        records = list(self._quarantine_cache.values())
        if active_only:
            records = [r for r in records if r.is_active]
        return sorted(records, key=lambda r: r.quarantined_at, reverse=True)

    def resolve_quarantine(
        self,
        quarantine_id: str,
        resolved_by: str,
        resolution_notes: str,
    ) -> Optional[QuarantineRecord]:
        """Resolve an active quarantine with forensic rationale and analyst identity."""
        record = self._quarantine_cache.get(quarantine_id)
        if not record:
            out_path = self.quarantine_dir / f"{quarantine_id}.json"
            if not out_path.exists():
                return None
            with open(out_path, "r", encoding="utf-8") as f:
                record = QuarantineRecord.model_validate(json.load(f))

        record.is_active = False
        record.resolved_at = datetime.now(timezone.utc)
        record.resolved_by = resolved_by
        record.resolution_notes = resolution_notes

        self._quarantine_cache[quarantine_id] = record
        out_path = self.quarantine_dir / f"{quarantine_id}.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(record.model_dump(mode="json"), f, indent=2)

        return record

    # =========================================================================
    # Holistic Evidence Fusion & Central Assessment
    # =========================================================================

    def fuse(
        self,
        target_entity_id: str,
        evidence: List[EvidenceItem],
        strict_subject_binding: bool = False,
    ) -> FusedAssessment:
        """Fuse cross-layer evidence into an authoritative security assessment and verdict."""
        # Validate that all inputs have actual evidence IDs
        for e in evidence:
            if not e.evidence_id or not e.evidence_id.strip():
                raise ValueError("Every evidence item input must have a valid non-empty evidence_id.")

        # Subject binding check
        if strict_subject_binding:
            model_ids = {e.related_model_id for e in evidence if e.related_model_id}
            if len(model_ids) > 1:
                raise ValueError("Evidence subject mismatch: conflicting related_model_ids")
            dataset_ids = {e.related_dataset_id for e in evidence if e.related_dataset_id}
            if len(dataset_ids) > 1:
                raise ValueError("Evidence subject mismatch: conflicting related_dataset_ids")

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

        # 2. Hard Veto Checks
        hard_veto_triggered = False
        veto_reasons: List[str] = []
        decisive_evidence: List[str] = []

        for e in evidence:
            desc_lower = e.description.lower()

            # Rule A: Cryptographic signature failure / forgery
            if (e.source == EvidenceSource.CRYPTO_VERIFICATION or "signature" in desc_lower or "forger" in desc_lower) and e.severity == IntegritySeverity.CRITICAL:
                hard_veto_triggered = True
                veto_reasons.append("Invalid or forged cryptographic signature detected.")
                decisive_evidence.append(e.evidence_id)

            # Rule B: Broken inference provenance / replay attack
            if e.source == EvidenceSource.INFERENCE_DNA and e.severity == IntegritySeverity.CRITICAL:
                if any(k in desc_lower for k in ["replay", "tamper", "broken", "mismatch", "reuse", "break"]):
                    hard_veto_triggered = True
                    veto_reasons.append("Inference provenance chain broken or replay attack detected.")
                    decisive_evidence.append(e.evidence_id)

            # Rule C: Model identity hash mismatch / unauthorized substitution
            if e.source == EvidenceSource.MODEL_IDENTITY and e.severity == IntegritySeverity.CRITICAL:
                if any(k in desc_lower for k in ["mismatch", "substitution", "tamper", "unauthorized", "discrepancy", "modified", "mutation"]):
                    hard_veto_triggered = True
                    veto_reasons.append("Model identity hash mismatch: unauthorized model substitution or weight modification detected.")
                    decisive_evidence.append(e.evidence_id)

            # Rule D: Dataset tampering / poisoning trigger (critical severity)
            if e.source == EvidenceSource.DATA_INTEGRITY and e.severity == IntegritySeverity.CRITICAL:
                if any(k in desc_lower for k in ["tamper", "mismatch", "backdoor", "trigger", "poison"]):
                    hard_veto_triggered = True
                    veto_reasons.append("Critical training data tampering or backdoor trigger pattern detected.")
                    decisive_evidence.append(e.evidence_id)

        # 3. Weighted risk computation
        # DRIFT ISOLATION RULE: Statistical distribution shift ALONE never triggers hard veto / automatic quarantine
        non_drift_critical = any(
            e.severity == IntegritySeverity.CRITICAL and e.source != EvidenceSource.DISTRIBUTION_SHIFT
            for e in evidence
        )

        raw_weighted_risk = 0.0
        for source, weight in SOURCE_WEIGHTS.items():
            source_items = [e for e in evidence if e.source == source]
            if source_items:
                max_sev = max(SEVERITY_MULTIPLIERS[e.severity] for e in source_items)
                raw_weighted_risk += weight * max_sev

        if hard_veto_triggered or non_drift_critical:
            raw_weighted_risk = max(raw_weighted_risk, 0.90)
        elif any(e.severity == IntegritySeverity.CRITICAL for e in evidence):
            raw_weighted_risk = max(raw_weighted_risk, 0.50)
        elif any(e.severity == IntegritySeverity.HIGH for e in evidence):
            raw_weighted_risk = max(raw_weighted_risk, 0.50)
        elif any(e.severity == IntegritySeverity.MEDIUM for e in evidence):
            raw_weighted_risk = max(raw_weighted_risk, 0.35)

        # Ensure drift alone caps at 0.65 (UNDER_REVIEW) unless corroborated
        only_drift = evidence and all(e.source == EvidenceSource.DISTRIBUTION_SHIFT for e in evidence)
        if only_drift and not hard_veto_triggered:
            raw_weighted_risk = min(raw_weighted_risk, 0.65)

        # Corroborated drift attack (drift + behavioral divergence / weight tampering) elevated to quarantine
        has_drift = any(e.source == EvidenceSource.DISTRIBUTION_SHIFT for e in evidence)
        has_behavior_or_weight = any(
            e.source in (EvidenceSource.BEHAVIOURAL_FINGERPRINT, EvidenceSource.MODEL_IDENTITY)
            and e.severity in (IntegritySeverity.HIGH, IntegritySeverity.CRITICAL)
            for e in evidence
        )
        if has_drift and has_behavior_or_weight:
            raw_weighted_risk = max(raw_weighted_risk, 0.85)

        risk_score = round(float(max(0.0, min(1.0, raw_weighted_risk))), 4)

        # 4. Confidence calculation
        volume_factor = min(len(evidence) / 5.0, 1.0)
        confidence_score = round(coverage_ratio * (0.5 + 0.5 * volume_factor), 4)

        # 5. Correlate threat narratives
        correlated_findings = ThreatCorrelator.correlate(evidence)

        # 6. Authoritative Gatekeeper Decision & Status
        if hard_veto_triggered:
            risk_level = AssuranceRiskLevel.CRITICAL
            overall_status = AssetStatus.QUARANTINED
            action = AssuranceAction.BLOCK
        elif risk_score >= 0.70:
            risk_level = AssuranceRiskLevel.CRITICAL
            overall_status = AssetStatus.QUARANTINED
            action = AssuranceAction.BLOCK
        elif risk_score >= 0.30:
            risk_level = AssuranceRiskLevel.HIGH if risk_score >= 0.50 else AssuranceRiskLevel.MEDIUM
            overall_status = AssetStatus.UNDER_REVIEW
            action = AssuranceAction.REVIEW
        else:
            risk_level = AssuranceRiskLevel.LOW
            overall_status = AssetStatus.ACCEPTED
            action = AssuranceAction.ALLOW

        # Auto-quarantine if quarantined
        if overall_status == AssetStatus.QUARANTINED:
            q_reason = veto_reasons[0] if veto_reasons else f"Risk score {risk_score:.4f} exceeded threshold 0.70"
            self.quarantine_entity(
                subject_id=target_entity_id,
                reason=q_reason,
                evidence_ids=decisive_evidence or [e.evidence_id for e in evidence],
                subject_type="ASSET",
            )

        # Contributor aggregation: real contributor identities only, unknown remains UNKNOWN
        contributors_set: Set[str] = set()
        for e in evidence:
            c = e.metadata.get("contributor") or e.metadata.get("contributor_id")
            if c:
                clean_c = str(c).strip()
                if clean_c and clean_c.lower() not in ("unknown", "anonymous", "none", "null"):
                    contributors_set.add(clean_c)
                else:
                    contributors_set.add("UNKNOWN")
        contributors = sorted(list(contributors_set)) if contributors_set else ["UNKNOWN"]

        # Recommended actions
        recommended_actions: List[str] = []
        if action == AssuranceAction.BLOCK:
            recommended_actions.append("QUARANTINE asset immediately; notify SOC and revoke active deployment credentials.")
            if veto_reasons:
                recommended_actions.extend([f"Investigate {r}" for r in veto_reasons])
        elif action == AssuranceAction.REVIEW:
            recommended_actions.append("FLAG for security officer and ML engineer secondary review.")
            if only_drift:
                recommended_actions.append("Inspect field operating environment, lighting, and sensor telemetry for operational shift.")
        else:
            recommended_actions.append("ALLOW asset promotion to operational pipeline.")

        limitations: List[str] = [
            f"Audit coverage ratio: {coverage.coverage_ratio * 100:.0f}%.",
            "Offline deterministic assurance without reliance on third-party cloud trust oracles.",
        ]
        if coverage.missing_sources:
            missing_names = ", ".join([s.value for s in coverage.missing_sources])
            limitations.append(f"Unchecked evidence sources: {missing_names}.")

        explanation_parts = []
        if veto_reasons:
            explanation_parts.append("HARD VETO: " + "; ".join(veto_reasons))
        if correlated_findings:
            explanation_parts.append("CORRELATED FINDINGS: " + "; ".join(correlated_findings))
        if not explanation_parts:
            explanation_parts.append(f"All {len(evidence)} evidence items verified without critical security violations.")
        explanation = " | ".join(explanation_parts)

        assessment_id = f"fused_{uuid.uuid4().hex[:12]}"
        created_at = datetime.now(timezone.utc)

        digest_payload = {
            "assessment_id": assessment_id,
            "target_entity_id": target_entity_id,
            "overall_status": overall_status.value,
            "risk_level": risk_level.value,
            "risk_score": risk_score,
            "confidence": confidence_score,
            "action": action.value,
            "coverage": coverage.model_dump(),
            "findings": correlated_findings,
            "contributors": contributors,
            "recommended_actions": recommended_actions,
            "limitations": limitations,
            "decisive_evidence": decisive_evidence,
            "hard_veto_triggered": hard_veto_triggered,
            "veto_reasons": veto_reasons,
            "raw_evidence": [e.model_dump() for e in evidence],
        }
        assessment_digest = canonical_json_hash(digest_payload)

        # Sign digest
        signature = None
        try:
            signature = self.key_manager.sign_hash(assessment_digest)
        except Exception:
            pass

        assessment = FusedAssessment(
            assessment_id=assessment_id,
            target_entity_id=target_entity_id,
            overall_status=overall_status,
            verdict=overall_status,
            risk_level=risk_level,
            risk_score=risk_score,
            confidence=confidence_score,
            confidence_score=confidence_score,
            action=action,
            coverage=coverage,
            findings=correlated_findings,
            correlated_findings=correlated_findings,
            contributors=contributors,
            recommended_actions=recommended_actions,
            limitations=limitations,
            explanation=explanation,
            raw_evidence=evidence,
            decisive_evidence=decisive_evidence,
            hard_veto_triggered=hard_veto_triggered,
            veto_reasons=veto_reasons,
            signature=signature,
            assessment_digest=assessment_digest,
            created_at=created_at,
        )

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
