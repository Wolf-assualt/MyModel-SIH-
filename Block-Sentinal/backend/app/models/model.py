"""Model and ModelFingerprint entities for model-agnostic integrity assurance."""
import uuid
from typing import List, Optional, TYPE_CHECKING
from sqlalchemy import String, Integer, BigInteger, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin

if TYPE_CHECKING:
    from app.models.inference import InferenceRecord


class Model(Base, TimestampMixin):
    """Registered CV model entity (ONNX, PyTorch, TorchScript)."""
    __tablename__ = "models"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    framework: Mapped[str] = mapped_column(String(50), nullable=False)  # ONNX, PyTorch, TorchScript
    format: Mapped[str] = mapped_column(String(50), nullable=False)     # .onnx, .pt, .pth, .ts
    version: Mapped[str] = mapped_column(String(50), default="1.0.0", nullable=False)
    file_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    sha256_digest: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    parameters_count: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    metadata_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    fingerprints: Mapped[List["ModelFingerprint"]] = relationship("ModelFingerprint", back_populates="model", cascade="all, delete-orphan")
    inferences: Mapped[List["InferenceRecord"]] = relationship("InferenceRecord", back_populates="model")


class ModelFingerprint(Base, TimestampMixin):
    """Cryptographic and behavioural fingerprint of a registered model."""
    __tablename__ = "model_fingerprints"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    model_id: Mapped[str] = mapped_column(String(36), ForeignKey("models.id", ondelete="CASCADE"), nullable=False)
    weights_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    parameter_stats_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    activation_stats_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    behavioral_vector_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    benchmark_digest: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # Relationships
    model: Mapped["Model"] = relationship("Model", back_populates="fingerprints")
