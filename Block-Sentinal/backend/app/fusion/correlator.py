"""Cross-layer threat correlation engine for multi-contributor CV assurance."""
from typing import List

from app.schemas.fusion import EvidenceItem, EvidenceSource
from app.schemas.integrity import IntegritySeverity


class ThreatCorrelator:
    """Synthesizes cross-layer verification evidence into correlated threat narratives."""

    @classmethod
    def correlate(cls, evidence: List[EvidenceItem]) -> List[str]:
        """Evaluate cross-layer rules to identify composite attacks and operational shifts."""
        findings: List[str] = []

        # Index evidence by source
        by_source = {s: [e for e in evidence if e.source == s] for s in EvidenceSource}

        # Helper predicates with stem matching
        has_data_backdoor = any(
            e.severity in (IntegritySeverity.HIGH, IntegritySeverity.CRITICAL)
            and any(k in e.description.lower() for k in ["trigger", "backdoor", "poison"])
            for e in by_source[EvidenceSource.DATA_INTEGRITY]
        )

        has_model_divergence = any(
            e.severity in (IntegritySeverity.HIGH, IntegritySeverity.CRITICAL)
            and any(k in e.description.lower() for k in ["diverg", "quarantin", "cosine", "drift"])
            for e in by_source[EvidenceSource.BEHAVIOURAL_FINGERPRINT]
        )

        has_dna_tamper = any(
            e.severity in (IntegritySeverity.HIGH, IntegritySeverity.CRITICAL)
            and any(k in e.description.lower() for k in ["tamper", "replay", "mismatch", "signature", "forger"])
            for e in by_source[EvidenceSource.INFERENCE_DNA]
        )

        has_model_identity_mismatch = any(
            e.severity in (IntegritySeverity.HIGH, IntegritySeverity.CRITICAL)
            and any(k in e.description.lower() for k in ["mismatch", "tamper", "unauthoriz", "hash"])
            for e in by_source[EvidenceSource.MODEL_IDENTITY]
        )

        has_adversarial_drift = any(
            e.severity in (IntegritySeverity.HIGH, IntegritySeverity.CRITICAL)
            and any(k in e.description.lower() for k in ["adversarial", "anomaly", "entropy", "collapse", "severe", "shift", "drift"])
            for e in by_source[EvidenceSource.DISTRIBUTION_SHIFT]
        )

        has_model_weight_discrepancy = any(
            e.severity in (IntegritySeverity.HIGH, IntegritySeverity.CRITICAL)
            for e in by_source[EvidenceSource.MODEL_IDENTITY]
        )

        has_operational_drift = any(
            any(k in e.description.lower() for k in ["operational", "environmental", "illumination", "sensor", "dusk"])
            for e in by_source[EvidenceSource.DISTRIBUTION_SHIFT]
        )

        # 1. Rule 1: Targeted Backdoor Poisoning Campaign
        if has_data_backdoor and has_model_divergence:
            findings.append(
                "Correlated Targeted Backdoor Poisoning Campaign detected: Training data contains synthetic "
                "trigger artifacts that directly correlate with model behavioural divergence."
            )

        # 2. Rule 2: Model Substitution & Telemetry Tampering
        if has_dna_tamper and has_model_identity_mismatch:
            findings.append(
                "Unauthorized Model Substitution and In-Flight Telemetry Tampering detected: Model identity hash "
                "mismatch co-occurs with compromised inference receipt DNA."
            )

        # 3. Rule 3: Coordinated Evasion / Adversarial Perturbation Attack
        if has_adversarial_drift and has_model_divergence:
            findings.append(
                "Coordinated Evasion / Adversarial Perturbation Attack detected: Severe distribution anomaly "
                "correlates with model output divergence across perturbation batteries."
            )

        # Rule 3b: Drift + Model integrity discrepancy
        if has_adversarial_drift and has_model_weight_discrepancy:
            findings.append(
                "Input distribution anomalies accompany model weight integrity discrepancies: "
                "Suspicious model divergence under distributional shifts."
            )

        # 4. Rule 4: Benign Operational Environmental Drift
        if has_operational_drift and not has_dna_tamper and not has_model_identity_mismatch and not has_data_backdoor:
            findings.append(
                "Benign Operational Environmental Drift (Sensor/Lighting): Optical and illumination variance "
                "detected without underlying model tampering, backdoor triggers, or telemetry manipulation."
            )

        # 5. Standalone Critical Alerts (if not already subsumed by multi-layer correlation)
        if has_dna_tamper and not (has_dna_tamper and has_model_identity_mismatch):
            findings.append("Cryptographic Provenance Failure: Inference DNA tampering or replay detected.")

        if has_model_identity_mismatch and not (has_dna_tamper and has_model_identity_mismatch):
            findings.append("Model Identity Compromise: Active model weights mismatch reference baseline manifest.")

        if has_data_backdoor and not (has_data_backdoor and has_model_divergence):
            findings.append("Data Poisoning Indicator: Backdoor trigger patterns detected in training partition.")

        return findings
