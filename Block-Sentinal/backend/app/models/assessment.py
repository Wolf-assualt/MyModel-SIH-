"""AssuranceAssessment entity representing comprehensive multi-engine assurance decisions."""
import uuid
from typing import List, Optional, TYPE_CHECKING
from sqlalchemy import String, Float, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin

if TYPE_CHECKING:
    from app.models.finding import Finding


class AssuranceAssessment(Base, TimestampMixin):
    """Overall system or asset assurance assessment."""
    __tablename__ = "assurance_assessments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target_type: Mapped[str] = mapped_column(String(50), nullable=False)  # DATASET, MODEL, INFERENCE, PIPELINE
    target_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    # Core Intelligence Metrics
    overall_assurance_score: Mapped[float] = mapped_column(Float, nullable=False)  # 0.0 to 100.0
    risk_level: Mapped[str] = mapped_column(String(50), nullable=False)             # LOW, MEDIUM, HIGH, CRITICAL
    confidence: Mapped[float] = mapped_column(Float, nullable=False)                 # 0.0 to 1.0
    evidence_coverage: Mapped[float] = mapped_column(Float, nullable=False)          # 0.0 to 1.0

    # Disposition: ACCEPT, REVIEW, QUARANTINE
    recommended_disposition: Mapped[str] = mapped_column(String(50), nullable=False)

    # Detailed Subsystem Assessment Breakdowns
    data_assessment_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    model_assessment_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    inference_assessment_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    distribution_assessment_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Transparency & Explainability
    limitations_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    supported_attack_classes_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    findings: Mapped[List["Finding"]] = relationship("Finding", back_populates="assessment", cascade="all, delete-orphan")
