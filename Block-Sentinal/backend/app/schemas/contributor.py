"""Contributor validation schemas."""
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, ConfigDict
from app.schemas.common import RiskLevel


class ContributorBase(BaseModel):
    name: str = Field(..., min_length=2, max_length=255)
    organization: str = Field(default="Unknown", max_length=255)
    public_key: Optional[str] = None


class ContributorCreate(ContributorBase):
    pass


class ContributorUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=255)
    organization: Optional[str] = Field(None, max_length=255)
    public_key: Optional[str] = None


class ContributorResponse(ContributorBase):
    id: str
    trust_score: float = Field(..., ge=0.0, le=1.0)
    total_samples: int = Field(..., ge=0)
    suspicious_samples: int = Field(..., ge=0)
    duplicate_rate: float = Field(..., ge=0.0, le=1.0)
    near_duplicate_rate: float = Field(..., ge=0.0, le=1.0)
    label_anomaly_rate: float = Field(..., ge=0.0, le=1.0)
    ood_rate: float = Field(..., ge=0.0, le=1.0)
    trigger_rate: float = Field(..., ge=0.0, le=1.0)
    risk_level: RiskLevel
    overall_risk: float = Field(..., ge=0.0, le=1.0)
    confidence: float = Field(..., ge=0.0, le=1.0)
    evidence_coverage: float = Field(..., ge=0.0, le=1.0)
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ContributorRiskSummary(BaseModel):
    contributor_id: str
    name: str
    risk_level: RiskLevel
    overall_risk: float
    confidence: float
    evidence_coverage: float
    total_samples: int
    suspicious_samples: int

    model_config = ConfigDict(from_attributes=True)
