"""Sample model representing individual computer vision image/annotation items."""
import uuid
from typing import List, Optional, TYPE_CHECKING
from sqlalchemy import String, Text, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin

if TYPE_CHECKING:
    from app.models.dataset import DatasetBatch
    from app.models.contributor import Contributor
    from app.models.inference import InferenceRecord
    from app.models.finding import Finding


class Sample(Base, TimestampMixin):
    """Sample entity with cryptographic digest and perceptual fingerprint."""
    __tablename__ = "samples"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    batch_id: Mapped[str] = mapped_column(String(36), ForeignKey("dataset_batches.id", ondelete="CASCADE"), nullable=False)
    contributor_id: Mapped[str] = mapped_column(String(36), ForeignKey("contributors.id", ondelete="CASCADE"), nullable=False)

    file_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    sha256_digest: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    perceptual_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    label: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    split: Mapped[str] = mapped_column(String(20), default="train", nullable=False)
    metadata_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    batch: Mapped["DatasetBatch"] = relationship("DatasetBatch", back_populates="samples")
    contributor: Mapped["Contributor"] = relationship("Contributor", back_populates="samples")
    inferences: Mapped[List["InferenceRecord"]] = relationship("InferenceRecord", back_populates="sample")
    findings: Mapped[List["Finding"]] = relationship("Finding", back_populates="sample")

    __table_args__ = (
        Index("idx_sample_contributor_digest", "contributor_id", "sha256_digest"),
    )
