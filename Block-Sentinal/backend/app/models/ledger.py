"""SQLAlchemy model for the Tamper-Evident Assurance Ledger."""
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, DateTime, Text, Index
from app.ledger.database import LedgerBase


class LedgerEvent(LedgerBase):
    """Single event in the tamper-evident assurance ledger.
    
    Each event contains:
    - sequence: Monotonically increasing sequence number
    - timestamp: UTC timestamp of event creation
    - event_type: Type of event (ingestion, finding, model_registration, etc.)
    - actor: System or user who initiated the event
    - scan_id: Associated scan session ID (if applicable)
    - entity_id: ID of the entity being acted upon
    - payload_hash: SHA-256 hash of the event payload
    - previous_hash: Hash of the previous event in the chain
    - current_hash: Hash of this event (chain link)
    - signature: ECDSA signature (for signed events)
    """
    __tablename__ = "ledger_events"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    sequence = Column(Integer, unique=True, nullable=False, index=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    event_type = Column(String(100), nullable=False, index=True)
    actor = Column(String(255), nullable=False)
    scan_id = Column(String(100), nullable=True, index=True)
    entity_id = Column(String(255), nullable=False, index=True)
    payload_hash = Column(String(64), nullable=False)
    previous_hash = Column(String(64), nullable=False)
    current_hash = Column(String(64), nullable=False, unique=True)
    signature = Column(Text, nullable=True)  # Optional for unsigned events
    signing_key_fingerprint = Column(String(64), nullable=True)
    
    __table_args__ = (
        Index('idx_scan_entity', 'scan_id', 'entity_id'),
        Index('idx_event_timestamp', 'event_type', 'timestamp'),
    )
    
    def to_dict(self):
        """Convert ledger event to dictionary for serialization."""
        return {
            "sequence": self.sequence,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "event_type": self.event_type,
            "actor": self.actor,
            "scan_id": self.scan_id,
            "entity_id": self.entity_id,
            "payload_hash": self.payload_hash,
            "previous_hash": self.previous_hash,
            "current_hash": self.current_hash,
            "signature": self.signature,
            "signing_key_fingerprint": self.signing_key_fingerprint,
        }