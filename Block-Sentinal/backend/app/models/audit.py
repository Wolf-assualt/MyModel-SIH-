"""AuditEvent and MerkleRoot models providing tamper-evident hash chaining and audit integrity."""
import uuid
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import String, Integer, Text, DateTime, Index
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class AuditEvent(Base):
    """Tamper-evident audit ledger entry with cryptographic hash chaining."""
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    sequence_number: Mapped[int] = mapped_column(Integer, unique=True, nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    entity_type: Mapped[str] = mapped_column(String(50), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    actor: Mapped[str] = mapped_column(String(100), default="SYSTEM", nullable=False)

    # Cryptographic Chain Linkage
    payload_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    prev_event_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    event_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    signature: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    __table_args__ = (
        Index("idx_audit_seq_hash", "sequence_number", "event_hash"),
    )


class MerkleRoot(Base):
    """Merkle root tree anchor for batch-level verification without network dependency."""
    __tablename__ = "merkle_roots"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    batch_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    root_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    leaf_count: Mapped[int] = mapped_column(Integer, nullable=False)
    block_height: Mapped[int] = mapped_column(Integer, unique=True, nullable=False, index=True)
    finalized_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
