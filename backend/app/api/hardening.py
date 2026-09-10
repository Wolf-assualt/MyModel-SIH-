"""System Hardening and Security Audit Endpoints."""
from typing import Any, Dict
from fastapi import APIRouter

from app.core.hardening import default_integrity_auditor
from app.schemas.base import ResponseEnvelope

router = APIRouter(prefix="/hardening", tags=["System Hardening & Audit"])


@router.get("/audit/chain", response_model=ResponseEnvelope[Dict[str, Any]])
def audit_hash_chain() -> ResponseEnvelope[Dict[str, Any]]:
    """Audit the complete sequential hash chain from genesis block to current tip."""
    audit_report = default_integrity_auditor.audit_full_hash_chain()
    return ResponseEnvelope(data=audit_report)


@router.get("/audit/offline", response_model=ResponseEnvelope[Dict[str, Any]])
def verify_offline_readiness() -> ResponseEnvelope[Dict[str, Any]]:
    """Verify system operates in strictly air-gapped mode with zero external network connectivity."""
    offline_status = default_integrity_auditor.verify_offline_mode()
    return ResponseEnvelope(data=offline_status)


@router.get("/benchmark", response_model=ResponseEnvelope[Dict[str, Any]])
def get_performance_benchmarks() -> ResponseEnvelope[Dict[str, Any]]:
    """Execute on-demand cryptographic and throughput performance benchmark."""
    benchmarks = default_integrity_auditor.get_benchmark_metrics()
    return ResponseEnvelope(data=benchmarks)
