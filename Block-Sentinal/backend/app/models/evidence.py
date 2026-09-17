"""Evidence entity providing granular, reproducible mathematical proof for findings."""
import uuid
from typing import Optional, TYPE_CHECKING
from sqlalchemy import String, Float, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin

if TYPE_CHECKING:
    from app.models.finding import Finding


class Evidence(Base, TimestampMixin):
    """Granular evidence artifact supporting a finding."""
    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    finding_id: Mapped[str] = mapped_column(String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False)

    evidence_type: Mapped[str] = mapped_column(String(50), nullable=False)  # HASH_PROOF, STATISTICAL_METRIC, EMBEDDING_DISTANCE
    metric_name: Mapped[str] = mapped_column(String(100), nullable=False)
    metric_value: Mapped[float] = mapped_column(Float, nullable=False)
    raw_payload_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    sha256_proof: Mapped[str] = mapped_column(String(64), nullable=False)

    # Relationships
    finding: Mapped["Finding"] = relationship("Finding", back_populates="evidence_items")
