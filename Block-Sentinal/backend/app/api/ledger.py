"""API endpoints for the Tamper-Evident Assurance Ledger."""
from fastapi import APIRouter, Depends, HTTPException
from typing import Dict, List, Optional

from app.schemas.base import ResponseEnvelope
from app.ledger.engine import LedgerEngine
from app.ledger.database import get_ledger_db

router = APIRouter(prefix="/ledger", tags=["Tamper-Evident Ledger"])


@router.get("/verify", response_model=ResponseEnvelope[Dict])
def verify_ledger(db=Depends(get_ledger_db)):
    """Verify the integrity of the entire ledger hash chain.
    
    Returns verification results including:
    - valid: Whether the chain is valid
    - events_checked: Number of events checked
    - last_verified_sequence: Last sequence number verified
    - first_invalid_sequence: First invalid sequence if failed
    - failure_reason: Reason for failure
    """
    ledger = LedgerEngine(db)
    result = ledger.verify_chain()
    return ResponseEnvelope(data=result)


@router.get("/events", response_model=ResponseEnvelope[List[Dict]])
def get_all_events(limit: Optional[int] = None, db=Depends(get_ledger_db)):
    """Get all ledger events, optionally limited."""
    ledger = LedgerEngine(db)
    events = ledger.get_all_events(limit=limit)
    return ResponseEnvelope(data=[event.to_dict() for event in events])


@router.get("/events/scan/{scan_id}", response_model=ResponseEnvelope[List[Dict]])
def get_events_by_scan(scan_id: str, db=Depends(get_ledger_db)):
    """Get all ledger events for a specific scan."""
    ledger = LedgerEngine(db)
    events = ledger.get_events_by_scan(scan_id)
    return ResponseEnvelope(data=[event.to_dict() for event in events])


@router.get("/events/entity/{entity_id}", response_model=ResponseEnvelope[List[Dict]])
def get_events_by_entity(entity_id: str, db=Depends(get_ledger_db)):
    """Get all ledger events for a specific entity."""
    ledger = LedgerEngine(db)
    events = ledger.get_events_by_entity(entity_id)
    return ResponseEnvelope(data=[event.to_dict() for event in events])


@router.get("/events/type/{event_type}", response_model=ResponseEnvelope[List[Dict]])
def get_events_by_type(event_type: str, db=Depends(get_ledger_db)):
    """Get all ledger events of a specific type."""
    ledger = LedgerEngine(db)
    events = ledger.get_events_by_type(event_type)
    return ResponseEnvelope(data=[event.to_dict() for event in events])


@router.post("/decision", response_model=ResponseEnvelope[Dict])
def record_analyst_decision(
    entity_id: str,
    decision: str,
    actor: str,
    scan_id: Optional[str] = None,
    reason: Optional[str] = None,
    db=Depends(get_ledger_db),
):
    """Record an analyst decision (ACCEPT, REVIEW, QUARANTINE).
    
    Analyst decisions are cryptographically signed and recorded in the ledger.
    """
    if decision not in ["ACCEPT", "REVIEW", "QUARANTINE"]:
        raise HTTPException(status_code=400, detail="Invalid decision. Must be ACCEPT, REVIEW, or QUARANTINE")
    
    ledger = LedgerEngine(db)
    event = ledger.record_analyst_decision(
        entity_id=entity_id,
        decision=decision,
        actor=actor,
        scan_id=scan_id,
        reason=reason,
    )
    return ResponseEnvelope(data=event.to_dict())