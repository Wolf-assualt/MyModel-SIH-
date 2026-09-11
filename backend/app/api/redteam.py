"""Red-Team and Attack Lab API Endpoints."""
from fastapi import APIRouter

from app.redteam.runner import default_redteam_lab
from app.schemas.base import ResponseEnvelope
from app.schemas.redteam import (
    AttackExecutionRequest,
    AttackExecutionResult,
    AttackVerificationReport,
)

router = APIRouter(prefix="/redteam", tags=["Red-Team & Attack Lab"])


@router.post("/attack/execute", response_model=ResponseEnvelope[AttackExecutionResult])
def execute_attack(request: AttackExecutionRequest) -> ResponseEnvelope[AttackExecutionResult]:
    """Execute an adversarial attack simulation in the quarantine sandbox."""
    result = default_redteam_lab.execute_attack(request)
    return ResponseEnvelope(data=result)


@router.post("/attack/verify", response_model=ResponseEnvelope[AttackVerificationReport])
def verify_attack_detection(attack_result: AttackExecutionResult) -> ResponseEnvelope[AttackVerificationReport]:
    """Verify if TRUST-CV defensive engines successfully detect and quarantine the attack."""
    report = default_redteam_lab.verify_detection(attack_result)
    return ResponseEnvelope(data=report)
