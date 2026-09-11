"""Red-Team Adversarial Validation Laboratory API Endpoints.

Phase 11: Controlled defensive scenario execution, detection coverage matrix,
scorecard evaluations, and forensic chain verification.
"""
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from app.redteam.lab import default_redteam_lab as validation_lab
from app.redteam.runner import default_redteam_lab as legacy_lab
from app.schemas.base import ResponseEnvelope
from app.schemas.redteam import (
    AttackExecutionRequest,
    AttackExecutionResult,
    AttackVerificationReport,
    DetectionCoverageMatrix,
    DetectionScorecard,
    RedTeamScenario,
    ScenarioCategory,
    ScenarioExecutionResult,
)

router = APIRouter(prefix="/redteam", tags=["Red-Team & Defensive Validation Lab"])


class ScenarioRunRequest(BaseModel):
    """Payload to trigger execution of a red-team scenario."""
    scenario_id: Optional[str] = Field(default=None, description="Scenario ID to execute. If omitted, runs all scenarios.")


@router.get("/scenarios", response_model=ResponseEnvelope[List[RedTeamScenario]])
def list_scenarios(
    category: Optional[ScenarioCategory] = Query(None, description="Filter scenarios by category"),
) -> ResponseEnvelope[List[RedTeamScenario]]:
    """List all registered defensive red-team validation scenarios."""
    scenarios = validation_lab.list_scenarios(category=category)
    return ResponseEnvelope(data=scenarios)


@router.get("/scenarios/{scenario_id}", response_model=ResponseEnvelope[RedTeamScenario])
def get_scenario(scenario_id: str) -> ResponseEnvelope[RedTeamScenario]:
    """Retrieve details for a specific red-team scenario."""
    scenario = validation_lab.get_scenario(scenario_id)
    if not scenario:
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario_id}' not found.")
    return ResponseEnvelope(data=scenario)


@router.post("/scenarios", response_model=ResponseEnvelope[RedTeamScenario])
def register_scenario(scenario: RedTeamScenario) -> ResponseEnvelope[RedTeamScenario]:
    """Register a custom defensive validation scenario."""
    validation_lab.register_scenario(scenario)
    return ResponseEnvelope(data=scenario)


@router.post("/run", response_model=ResponseEnvelope[List[ScenarioExecutionResult]])
def run_scenarios(request: ScenarioRunRequest) -> ResponseEnvelope[List[ScenarioExecutionResult]]:
    """Execute a single red-team scenario or the entire validation suite."""
    if request.scenario_id:
        try:
            res = validation_lab.run_scenario(request.scenario_id)
            return ResponseEnvelope(data=[res])
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
    else:
        results = validation_lab.run_all_scenarios()
        return ResponseEnvelope(data=results)


@router.get("/results/{execution_id}", response_model=ResponseEnvelope[ScenarioExecutionResult])
def get_execution_result(execution_id: str) -> ResponseEnvelope[ScenarioExecutionResult]:
    """Retrieve detailed outcome of a past scenario execution."""
    res = validation_lab.get_result(execution_id)
    if not res:
        raise HTTPException(status_code=404, detail=f"Execution result '{execution_id}' not found.")
    return ResponseEnvelope(data=res)


@router.get("/coverage", response_model=ResponseEnvelope[DetectionCoverageMatrix])
def get_detection_coverage_matrix() -> ResponseEnvelope[DetectionCoverageMatrix]:
    """Retrieve machine-readable Detection Coverage Matrix across all assurance domains."""
    matrix = validation_lab.generate_coverage_matrix()
    return ResponseEnvelope(data=matrix)


@router.get("/scorecard", response_model=ResponseEnvelope[DetectionScorecard])
def get_detection_scorecard() -> ResponseEnvelope[DetectionScorecard]:
    """Retrieve aggregate Detection Scorecard with accuracy rates and category breakdown."""
    scorecard = validation_lab.generate_scorecard()
    return ResponseEnvelope(data=scorecard)


# Backward Compatibility Endpoints
@router.post("/attack/execute", response_model=ResponseEnvelope[AttackExecutionResult])
def execute_attack(request: AttackExecutionRequest) -> ResponseEnvelope[AttackExecutionResult]:
    """Execute an adversarial attack simulation in the quarantine sandbox (legacy)."""
    result = legacy_lab.execute_attack(request)
    return ResponseEnvelope(data=result)


@router.post("/attack/verify", response_model=ResponseEnvelope[AttackVerificationReport])
def verify_attack_detection(attack_result: AttackExecutionResult) -> ResponseEnvelope[AttackVerificationReport]:
    """Verify if TRUST-CV defensive engines successfully detect and quarantine the attack (legacy)."""
    report = legacy_lab.verify_detection(attack_result)
    return ResponseEnvelope(data=report)
