"""Tamper-Evident Assurance Ledger Engine.

Provides persistent, tamper-evident audit logging for all security events
using SQLite storage and hash-chain verification.
"""
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.core.config import settings
from app.crypto.canonical import canonical_json_dumps, canonical_json_hash
from app.crypto.signer import KeyManager, default_key_manager
from app.models.ledger import LedgerEvent
from app.db.base import Base


class LedgerEngine:
    """Manages the tamper-evident assurance ledger with SQLite persistence."""
    
    def __init__(self, db_session: Session, key_manager: Optional[KeyManager] = None):
        """Initialize ledger engine with database session and optional key manager."""
        self.db = db_session
        self.key_manager = key_manager or default_key_manager
        self._verified = False
        self._verification_result = None
        
    def _compute_event_hash(
        self,
        sequence: int,
        timestamp: str,
        event_type: str,
        actor: str,
        scan_id: Optional[str],
        entity_id: str,
        payload_hash: str,
        previous_hash: str,
    ) -> str:
        """Compute the current hash for a ledger event using canonical serialization."""
        event_data = {
            "sequence": sequence,
            "timestamp": timestamp,
            "event_type": event_type,
            "actor": actor,
            "scan_id": scan_id,
            "entity_id": entity_id,
            "payload_hash": payload_hash,
            "previous_hash": previous_hash,
        }
        return canonical_json_hash(event_data)
    
    def _get_next_sequence(self) -> int:
        """Get the next sequence number for the ledger."""
        result = self.db.execute(select(LedgerEvent).order_by(LedgerEvent.sequence.desc()).limit(1))
        last_event = result.scalar_one_or_none()
        return (last_event.sequence + 1) if last_event else 0
    
    def _get_previous_hash(self) -> str:
        """Get the hash of the last event in the chain."""
        result = self.db.execute(select(LedgerEvent).order_by(LedgerEvent.sequence.desc()).limit(1))
        last_event = result.scalar_one_or_none()
        return last_event.current_hash if last_event else "0" * 64
    
    def append_event(
        self,
        event_type: str,
        entity_id: str,
        payload: Dict,
        actor: str = "system",
        scan_id: Optional[str] = None,
        sign: bool = False,
    ) -> LedgerEvent:
        """Append a new event to the ledger with hash-chain linkage.
        
        Args:
            event_type: Type of event (e.g., "ingestion", "finding", "model_registration")
            entity_id: ID of the entity being acted upon
            payload: Event payload (will be hashed)
            actor: System or user who initiated the event
            scan_id: Associated scan session ID (if applicable)
            sign: Whether to sign this event with ECDSA
            
        Returns:
            The created LedgerEvent
        """
        sequence = self._get_next_sequence()
        timestamp = datetime.now(timezone.utc).isoformat()
        previous_hash = self._get_previous_hash()
        payload_hash = canonical_json_hash(payload)
        
        current_hash = self._compute_event_hash(
            sequence=sequence,
            timestamp=timestamp,
            event_type=event_type,
            actor=actor,
            scan_id=scan_id,
            entity_id=entity_id,
            payload_hash=payload_hash,
            previous_hash=previous_hash,
        )
        
        signature = None
        if sign:
            signature = self.key_manager.sign_hash(current_hash)
        
        event = LedgerEvent(
            sequence=sequence,
            timestamp=datetime.fromisoformat(timestamp),
            event_type=event_type,
            actor=actor,
            scan_id=scan_id,
            entity_id=entity_id,
            payload_hash=payload_hash,
            previous_hash=previous_hash,
            current_hash=current_hash,
            signature=signature,
        )
        
        self.db.add(event)
        self.db.commit()
        self.db.refresh(event)
        
        return event
    
    def verify_chain(self) -> Dict:
        """Verify the integrity of the entire ledger hash chain.
        
        Returns:
            Dictionary with verification results:
            - valid: bool - Whether the chain is valid
            - events_checked: int - Number of events checked
            - last_verified_sequence: int - Last sequence number verified
            - first_invalid_sequence: Optional[int] - First invalid sequence if failed
            - failure_reason: Optional[str] - Reason for failure
        """
        result = self.db.execute(select(LedgerEvent).order_by(LedgerEvent.sequence.asc()))
        events = result.scalars().all()
        
        if not events:
            return {
                "valid": True,
                "events_checked": 0,
                "last_verified_sequence": -1,
                "first_invalid_sequence": None,
                "failure_reason": None,
            }
        
        events_checked = 0
        last_verified_sequence = -1
        
        for i, event in enumerate(events):
            # 1. Verify sequence continuity
            if event.sequence != i:
                return {
                    "valid": False,
                    "events_checked": events_checked,
                    "last_verified_sequence": last_verified_sequence,
                    "first_invalid_sequence": event.sequence,
                    "failure_reason": f"Sequence gap at index {i}: expected {i}, got {event.sequence}",
                }
            
            # 2. Verify previous hash pointer
            expected_prev = "0" * 64 if i == 0 else events[i - 1].current_hash
            if event.previous_hash != expected_prev:
                return {
                    "valid": False,
                    "events_checked": events_checked,
                    "last_verified_sequence": last_verified_sequence,
                    "first_invalid_sequence": event.sequence,
                    "failure_reason": f"Previous hash mismatch at sequence {event.sequence}",
                }
            
            # 3. Recompute and verify current hash
            # Ensure timestamp is in UTC ISO format for consistent hashing
            if event.timestamp:
                if event.timestamp.tzinfo is None:
                    # If timestamp is naive, treat as UTC
                    timestamp_str = event.timestamp.replace(tzinfo=timezone.utc).isoformat()
                else:
                    timestamp_str = event.timestamp.isoformat()
            else:
                timestamp_str = ""
            
            expected_current = self._compute_event_hash(
                sequence=event.sequence,
                timestamp=timestamp_str,
                event_type=event.event_type,
                actor=event.actor,
                scan_id=event.scan_id,
                entity_id=event.entity_id,
                payload_hash=event.payload_hash,
                previous_hash=event.previous_hash,
            )
            
            if event.current_hash != expected_current:
                return {
                    "valid": False,
                    "events_checked": events_checked,
                    "last_verified_sequence": last_verified_sequence,
                    "first_invalid_sequence": event.sequence,
                    "failure_reason": f"Current hash recomputation failed at sequence {event.sequence}",
                }
            
            # 4. Verify signature if present
            if event.signature:
                public_key_pem = self.key_manager.export_public_key_pem()
                if not KeyManager.verify_signature(public_key_pem, expected_current, event.signature):
                    return {
                        "valid": False,
                        "events_checked": events_checked,
                        "last_verified_sequence": last_verified_sequence,
                        "first_invalid_sequence": event.sequence,
                        "failure_reason": f"Invalid signature at sequence {event.sequence}",
                    }
            
            events_checked += 1
            last_verified_sequence = event.sequence
        
        return {
            "valid": True,
            "events_checked": events_checked,
            "last_verified_sequence": last_verified_sequence,
            "first_invalid_sequence": None,
            "failure_reason": None,
        }
    
    def get_events_by_scan(self, scan_id: str) -> List[LedgerEvent]:
        """Get all ledger events for a specific scan."""
        result = self.db.execute(
            select(LedgerEvent)
            .where(LedgerEvent.scan_id == scan_id)
            .order_by(LedgerEvent.sequence.asc())
        )
        return list(result.scalars().all())
    
    def get_events_by_entity(self, entity_id: str) -> List[LedgerEvent]:
        """Get all ledger events for a specific entity."""
        result = self.db.execute(
            select(LedgerEvent)
            .where(LedgerEvent.entity_id == entity_id)
            .order_by(LedgerEvent.sequence.asc())
        )
        return list(result.scalars().all())
    
    def get_events_by_type(self, event_type: str) -> List[LedgerEvent]:
        """Get all ledger events of a specific type."""
        result = self.db.execute(
            select(LedgerEvent)
            .where(LedgerEvent.event_type == event_type)
            .order_by(LedgerEvent.sequence.asc())
        )
        return list(result.scalars().all())
    
    def get_all_events(self, limit: Optional[int] = None) -> List[LedgerEvent]:
        """Get all ledger events, optionally limited."""
        query = select(LedgerEvent).order_by(LedgerEvent.sequence.asc())
        if limit:
            query = query.limit(limit)
        result = self.db.execute(query)
        return list(result.scalars().all())
    
    def record_analyst_decision(
        self,
        entity_id: str,
        decision: str,
        actor: str,
        scan_id: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> LedgerEvent:
        """Record an analyst decision (ACCEPT, REVIEW, QUARANTINE)."""
        payload = {
            "decision": decision,
            "reason": reason,
        }
        return self.append_event(
            event_type="analyst_decision",
            entity_id=entity_id,
            payload=payload,
            actor=actor,
            scan_id=scan_id,
            sign=True,  # Analyst decisions are signed
        )


# Global ledger directory
def ensure_ledger_directory() -> Path:
    """Ensure the ledger database directory exists."""
    ledger_dir = Path(settings.DATA_DIR) / "ledger"
    ledger_dir.mkdir(parents=True, exist_ok=True)
    return ledger_dir