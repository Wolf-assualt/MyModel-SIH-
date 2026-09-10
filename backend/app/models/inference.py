"""InferenceRecord entity representing the immutable Inference DNA and cryptographic provenance."""
import uuid
from datetime import datetime, timezone
from typing import List, Optional, TYPE_CHECKING
from sqlalchemy import String, Integer, Float, Text, DateTime, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.model import Model
    from app.models.sample import Sample
    from app.models.finding import Finding


class InferenceRecord(Base):
    """Inference DNA entity. Cryptographically binds input, model, configuration, output, and sequence."""
    __tablename__ = "inference_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    model_id: Mapped[str] = mapped_column(String(36), ForeignKey("models.id", ondelete="RESTRICT"), nullable=False)
    sample_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("samples.id", ondelete="SET NULL"), nullable=True)

    # Cryptographic Provenance Components (Inference DNA)
    input_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    model_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    preprocessing_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    config_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    output_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    # Prediction Payload
    prediction_json: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Chain & Anti-Replay Metadata
    nonce: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    sequence_number: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    prev_record_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    record_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    signature: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    model: Mapped["Model"] = relationship("Model", back_populates="inferences")
    sample: Mapped[Optional["Sample"]] = relationship("Sample", back_populates="inferences")
    findings: Mapped[List["Finding"]] = relationship("Finding", back_populates="inference")

    __table_args__ = (
        Index("idx_inf_seq_hash", "sequence_number", "record_hash"),
    )
