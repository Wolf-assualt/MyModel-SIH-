"""Finding entity representing structured, evidence-backed security or integrity alerts."""
import uuid
from typing import List, Optional, TYPE_CHECKING
from sqlalchemy import String, Float, Text, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin

if TYPE_CHECKING:
    from app.models.assessment import AssuranceAssessment
    from app.models.sample import Sample
    from app.models.inference import InferenceRecord
    from app.models.evidence import Evidence


class Finding(Base, TimestampMixin):
    """Structured finding. Connects alerts directly to evidence, confidence, limitations, and actions."""
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    assessment_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("assurance_assessments.id", ondelete="CASCADE"), nullable=True)
    sample_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("samples.id", ondelete="SET NULL"), nullable=True)
    inference_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("inference_records.id", ondelete="SET NULL"), nullable=True)

    # Finding Classification
    finding_type: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, index=True)  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    confidence: Mapped[float] = mapped_column(Float, nullable=False)                # 0.0 to 1.0

    # Asset Lineage
    affected_asset_type: Mapped[str] = mapped_column(String(50), nullable=False) # DATASET, SAMPLE, MODEL, INFERENCE, CONTRIBUTOR
    affected_asset_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    # Evidence, Limitations & Actionable Advice
    evidence_summary: Mapped[str] = mapped_column(Text, nullable=False)
    limitation: Mapped[str] = mapped_column(Text, nullable=False)
    recommended_action: Mapped[str] = mapped_column(Text, nullable=False)

    # Relationships
    assessment: Mapped[Optional["AssuranceAssessment"]] = relationship("AssuranceAssessment", back_populates="findings")
    sample: Mapped[Optional["Sample"]] = relationship("Sample", back_populates="findings")
    inference: Mapped[Optional["InferenceRecord"]] = relationship("InferenceRecord", back_populates="findings")
    evidence_items: Mapped[List["Evidence"]] = relationship("Evidence", back_populates="finding", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_finding_type_sev", "finding_type", "severity"),
    )
