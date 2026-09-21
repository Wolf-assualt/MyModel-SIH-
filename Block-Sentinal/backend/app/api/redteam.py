"""Red-Team and Attack Lab API Endpoints."""
from typing import Any, Dict, List, Optional
# pyrefly: ignore [missing-import]
from fastapi import APIRouter, HTTPException
# pyrefly: ignore [missing-import]
from pydantic import BaseModel

from app.redteam.lab import default_redteam_lab as validation_lab
from app.redteam.runner import default_redteam_lab as runner_lab
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

router = APIRouter(prefix="/redteam", tags=["Red-Team & Attack Lab"])


class ScenarioRunRequest(BaseModel):
    scenario_id: Optional[str] = None
    category: Optional[ScenarioCategory] = None


@router.post("/attack/execute", response_model=ResponseEnvelope[AttackExecutionResult])
def execute_attack(request: AttackExecutionRequest) -> ResponseEnvelope[AttackExecutionResult]:
    """Execute an adversarial attack simulation in the quarantine sandbox."""
    result = runner_lab.execute_attack(request)
    return ResponseEnvelope(data=result)


@router.post("/attack/verify", response_model=ResponseEnvelope[AttackVerificationReport])
def verify_attack_detection(attack_result: AttackExecutionResult) -> ResponseEnvelope[AttackVerificationReport]:
    """Verify if TRUST-CV defensive engines successfully detect and quarantine the attack."""
    report = runner_lab.verify_detection(attack_result)
    return ResponseEnvelope(data=report)


@router.get("/scenarios", response_model=ResponseEnvelope[List[RedTeamScenario]])
def list_scenarios(category: Optional[ScenarioCategory] = None) -> ResponseEnvelope[List[RedTeamScenario]]:
    """List all available defensive red-team scenarios."""
    scenarios = validation_lab.list_scenarios(category=category)
    return ResponseEnvelope(data=scenarios)


@router.get("/scenarios/{scenario_id}", response_model=ResponseEnvelope[RedTeamScenario])
def get_scenario(scenario_id: str) -> ResponseEnvelope[RedTeamScenario]:
    """Lookup a defensive red-team scenario by ID."""
    scen = validation_lab.get_scenario(scenario_id)
    if not scen:
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario_id}' not found")
    return ResponseEnvelope(data=scen)


@router.post("/run", response_model=ResponseEnvelope[List[ScenarioExecutionResult]])
def run_scenarios(request: ScenarioRunRequest) -> ResponseEnvelope[List[ScenarioExecutionResult]]:
    """Execute a single scenario or all scenarios in a category through the full assurance pipeline."""
    if request.scenario_id:
        res = validation_lab.run_scenario(request.scenario_id)
        return ResponseEnvelope(data=[res])
    elif request.category:
        scenarios = validation_lab.list_scenarios(category=request.category)
        results = [validation_lab.run_scenario(s.scenario_id) for s in scenarios]
        return ResponseEnvelope(data=results)
    else:
        results = validation_lab.run_all_scenarios()
        return ResponseEnvelope(data=results)


@router.get("/results/{execution_id}", response_model=ResponseEnvelope[ScenarioExecutionResult])
def get_scenario_result(execution_id: str) -> ResponseEnvelope[ScenarioExecutionResult]:
    """Retrieve forensic execution results for a specific scenario execution."""
    res = validation_lab.get_result(execution_id)
    if not res:
        raise HTTPException(status_code=404, detail=f"Execution result '{execution_id}' not found")
    return ResponseEnvelope(data=res)


@router.get("/coverage", response_model=ResponseEnvelope[DetectionCoverageMatrix])
def get_coverage_matrix() -> ResponseEnvelope[DetectionCoverageMatrix]:
    """Retrieve full matrix of defensive capabilities mapped across scenario mutations."""
    matrix = validation_lab.generate_coverage_matrix()
    return ResponseEnvelope(data=matrix)


@router.get("/scorecard", response_model=ResponseEnvelope[DetectionScorecard])
def get_detection_scorecard() -> ResponseEnvelope[DetectionScorecard]:
    """Retrieve system scorecard reflecting overall accuracy and false-positive resistance."""
    scorecard = validation_lab.generate_scorecard()
    return ResponseEnvelope(data=scorecard)
