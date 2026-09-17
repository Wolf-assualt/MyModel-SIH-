"""AssuranceAssessment schemas."""
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field, ConfigDict
from app.schemas.common import Disposition, RiskLevel
from app.schemas.finding import FindingResponse


class AssuranceAssessmentBase(BaseModel):
    target_type: str = Field(..., max_length=50)
    target_id: str = Field(..., max_length=64)
    overall_assurance_score: float = Field(..., ge=0.0, le=100.0)
    risk_level: str = Field(..., max_length=50)
    confidence: float = Field(..., ge=0.0, le=1.0)
    evidence_coverage: float = Field(..., ge=0.0, le=1.0)
    recommended_disposition: Disposition
    data_assessment_json: Optional[str] = None
    model_assessment_json: Optional[str] = None
    inference_assessment_json: Optional[str] = None
    distribution_assessment_json: Optional[str] = None
    limitations_json: Optional[str] = None
    supported_attack_classes_json: Optional[str] = None


class AssuranceAssessmentCreate(AssuranceAssessmentBase):
    pass


class AssuranceAssessmentResponse(AssuranceAssessmentBase):
    id: str
    created_at: datetime
    updated_at: datetime
    findings: List[FindingResponse] = []

    model_config = ConfigDict(from_attributes=True)


class AssuranceSummary(BaseModel):
    overall_assurance_score: float
    recommended_disposition: Disposition
    risk_level: str
    confidence: float
    evidence_coverage: float
    total_findings: int
    critical_findings: int
    high_findings: int
    active_quarantines: int

    model_config = ConfigDict(from_attributes=True)
