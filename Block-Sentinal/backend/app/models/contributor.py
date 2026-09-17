"""Contributor model representing data/model contributors and their aggregated risk metrics."""
import uuid
from typing import List, TYPE_CHECKING
from sqlalchemy import String, Float, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin

if TYPE_CHECKING:
    from app.models.dataset import Dataset
    from app.models.sample import Sample


class Contributor(Base, TimestampMixin):
    """Contributor entity. Aggregates sample-level findings without arbitrary malicious labeling."""
    __tablename__ = "contributors"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    organization: Mapped[str] = mapped_column(String(255), nullable=False, default="Unknown")
    public_key: Mapped[str] = mapped_column(Text, nullable=True)

    # Trust & Risk Aggregation
    trust_score: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    total_samples: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    suspicious_samples: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Disaggregated Rates
    duplicate_rate: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    near_duplicate_rate: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    label_anomaly_rate: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    ood_rate: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    trigger_rate: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    # Risk Disposition: 'Normal', 'Low Risk', 'Review', 'High Integrity Risk', 'Quarantine Recommended'
    risk_level: Mapped[str] = mapped_column(String(50), default="Normal", nullable=False)
    overall_risk: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    evidence_coverage: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)

    # Relationships
    datasets: Mapped[List["Dataset"]] = relationship("Dataset", back_populates="contributor", cascade="all, delete-orphan")
    samples: Mapped[List["Sample"]] = relationship("Sample", back_populates="contributor")
