"""Dataset and DatasetBatch models for COCO, YOLO, and custom image datasets."""
import uuid
from typing import List, TYPE_CHECKING
from sqlalchemy import String, Integer, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin

if TYPE_CHECKING:
    from app.models.contributor import Contributor
    from app.models.sample import Sample


class Dataset(Base, TimestampMixin):
    """Dataset entity representing an ingested collection of computer vision samples."""
    __tablename__ = "datasets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    format: Mapped[str] = mapped_column(String(50), nullable=False)  # COCO, YOLO, ImageFolder
    root_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    sha256_digest: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    total_samples: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    contributor_id: Mapped[str] = mapped_column(String(36), ForeignKey("contributors.id", ondelete="CASCADE"), nullable=False)

    # Relationships
    contributor: Mapped["Contributor"] = relationship("Contributor", back_populates="datasets")
    batches: Mapped[List["DatasetBatch"]] = relationship("DatasetBatch", back_populates="dataset", cascade="all, delete-orphan")


class DatasetBatch(Base, TimestampMixin):
    """Dataset batch entity allowing incremental batch ingestion and per-batch verification."""
    __tablename__ = "dataset_batches"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    dataset_id: Mapped[str] = mapped_column(String(36), ForeignKey("datasets.id", ondelete="CASCADE"), nullable=False)
    batch_number: Mapped[int] = mapped_column(Integer, nullable=False)
    sha256_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    sample_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="INGESTED", nullable=False)

    # Relationships
    dataset: Mapped["Dataset"] = relationship("Dataset", back_populates="batches")
    samples: Mapped[List["Sample"]] = relationship("Sample", back_populates="batch", cascade="all, delete-orphan")
