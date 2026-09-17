"""Finding and Evidence validation schemas."""
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field, ConfigDict
from app.schemas.common import FindingType, Severity


class EvidenceBase(BaseModel):
    evidence_type: str = Field(..., max_length=50)
    metric_name: str = Field(..., max_length=100)
    metric_value: float
    raw_payload_json: Optional[str] = None
    sha256_proof: str = Field(..., min_length=64, max_length=64)


class EvidenceCreate(EvidenceBase):
    finding_id: str


class EvidenceResponse(EvidenceBase):
    id: str
    finding_id: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class FindingBase(BaseModel):
    finding_type: FindingType
    severity: Severity
    confidence: float = Field(..., ge=0.0, le=1.0)
    affected_asset_type: str = Field(..., max_length=50)
    affected_asset_id: str = Field(..., max_length=64)
    evidence_summary: str
    limitation: str
    recommended_action: str


class FindingCreate(FindingBase):
    assessment_id: Optional[str] = None
    sample_id: Optional[str] = None
    inference_id: Optional[str] = None


class FindingResponse(FindingBase):
    id: str
    assessment_id: Optional[str] = None
    sample_id: Optional[str] = None
    inference_id: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    evidence_items: List[EvidenceResponse] = []

    model_config = ConfigDict(from_attributes=True)
