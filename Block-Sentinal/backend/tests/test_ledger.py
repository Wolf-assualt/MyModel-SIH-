"""Tests for the Tamper-Evident Assurance Ledger."""
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool

from app.ledger.engine import LedgerEngine
from app.ledger.database import LedgerBase, LedgerSessionLocal
from app.models.ledger import LedgerEvent
from app.crypto.signer import KeyManager


# In-memory SQLite for isolated ledger tests
TEST_LEDGER_URL = "sqlite:///:memory:"

test_ledger_engine = create_engine(
    TEST_LEDGER_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)

TestLedgerSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_ledger_engine)


@pytest.fixture(scope="function")
def ledger_db() -> Session:
    """Create a fresh ledger database for every test function."""
    LedgerBase.metadata.create_all(bind=test_ledger_engine)
    session = TestLedgerSessionLocal()
    try:
        yield session
    finally:
        session.close()
        LedgerBase.metadata.drop_all(bind=test_ledger_engine)


@pytest.fixture(scope="function")
def ledger(ledger_db: Session) -> LedgerEngine:
    """Provide a LedgerEngine instance with a fresh database."""
    key_manager = KeyManager()
    return LedgerEngine(ledger_db, key_manager=key_manager)


def test_append_event(ledger: LedgerEngine):
    """Test appending a single event to the ledger."""
    event = ledger.append_event(
        event_type="test_event",
        entity_id="test_entity",
        payload={"test": "data"},
        actor="test_actor",
    )
    
    assert event.sequence == 0
    assert event.event_type == "test_event"
    assert event.entity_id == "test_entity"
    assert event.actor == "test_actor"
    assert event.previous_hash == "0" * 64
    assert event.current_hash != "0" * 64
    assert event.signature is None


def test_append_multiple_events(ledger: LedgerEngine):
    """Test appending multiple events and verify sequence continuity."""
    event1 = ledger.append_event(
        event_type="event1",
        entity_id="entity1",
        payload={"seq": 1},
        actor="system",
    )
    
    event2 = ledger.append_event(
        event_type="event2",
        entity_id="entity2",
        payload={"seq": 2},
        actor="system",
    )
    
    event3 = ledger.append_event(
        event_type="event3",
        entity_id="entity3",
        payload={"seq": 3},
        actor="system",
    )
    
    assert event1.sequence == 0
    assert event2.sequence == 1
    assert event3.sequence == 2
    
    # Verify hash chain linkage
    assert event2.previous_hash == event1.current_hash
    assert event3.previous_hash == event2.current_hash


def test_verify_chain_empty(ledger: LedgerEngine):
    """Test verification of an empty ledger."""
    result = ledger.verify_chain()
    assert result["valid"] is True
    assert result["events_checked"] == 0
    assert result["last_verified_sequence"] == -1
    assert result["first_invalid_sequence"] is None
    assert result["failure_reason"] is None


def test_verify_chain_valid(ledger: LedgerEngine):
    """Test verification of a valid hash chain."""
    for i in range(5):
        ledger.append_event(
            event_type=f"event_{i}",
            entity_id=f"entity_{i}",
            payload={"index": i},
            actor="system",
        )
    
    result = ledger.verify_chain()
    print(f"Verification result: {result}")
    assert result["valid"] is True
    assert result["events_checked"] == 5
    assert result["last_verified_sequence"] == 4
    assert result["first_invalid_sequence"] is None
    assert result["failure_reason"] is None


def test_verify_chain_modified_event(ledger: LedgerEngine):
    """Test detection of a modified event in the chain."""
    event1 = ledger.append_event(
        event_type="event1",
        entity_id="entity1",
        payload={"original": "data"},
        actor="system",
    )
    
    ledger.append_event(
        event_type="event2",
        entity_id="entity2",
        payload={"seq": 2},
        actor="system",
    )
    
    # Tamper with the first event by changing a field that affects hash
    ledger.db.execute(
        text(f"UPDATE ledger_events SET entity_id = 'tampered_entity' WHERE sequence = {event1.sequence}")
    )
    ledger.db.commit()
    
    result = ledger.verify_chain()
    assert result["valid"] is False
    assert result["first_invalid_sequence"] == 0
    assert "Current hash recomputation failed" in result["failure_reason"]


def test_verify_chain_modified_payload_hash(ledger: LedgerEngine):
    """Test detection of modified payload hash."""
    event1 = ledger.append_event(
        event_type="event1",
        entity_id="entity1",
        payload={"original": "data"},
        actor="system",
    )
    
    # Tamper with payload hash
    ledger.db.execute(
        text(f"UPDATE ledger_events SET payload_hash = '0' * 64 WHERE sequence = {event1.sequence}")
    )
    ledger.db.commit()
    
    result = ledger.verify_chain()
    assert result["valid"] is False
    # The hash recomputation will fail because the payload_hash doesn't match the current_hash
    assert result["first_invalid_sequence"] == 0


def test_verify_chain_broken_previous_hash(ledger: LedgerEngine):
    """Test detection of broken previous_hash linkage."""
    ledger.append_event(
        event_type="event1",
        entity_id="entity1",
        payload={"seq": 1},
        actor="system",
    )
    
    event2 = ledger.append_event(
        event_type="event2",
        entity_id="entity2",
        payload={"seq": 2},
        actor="system",
    )
    
    # Break the previous_hash linkage
    ledger.db.execute(
        text(f"UPDATE ledger_events SET previous_hash = '0' * 64 WHERE sequence = {event2.sequence}")
    )
    ledger.db.commit()
    
    result = ledger.verify_chain()
    assert result["valid"] is False
    assert result["first_invalid_sequence"] == 1
    assert "Previous hash mismatch" in result["failure_reason"]


def test_verify_chain_sequence_gap(ledger: LedgerEngine):
    """Test detection of sequence gaps."""
    event1 = ledger.append_event(
        event_type="event1",
        entity_id="entity1",
        payload={"seq": 1},
        actor="system",
    )
    
    event2 = ledger.append_event(
        event_type="event2",
        entity_id="entity2",
        payload={"seq": 2},
        actor="system",
    )
    
    # Create a sequence gap by updating the second event's sequence
    ledger.db.execute(
        text(f"UPDATE ledger_events SET sequence = 10 WHERE sequence = {event2.sequence}")
    )
    ledger.db.commit()
    
    result = ledger.verify_chain()
    assert result["valid"] is False
    # The verification will detect the gap when it expects sequence 1 at index 1 but gets sequence 10
    assert result["first_invalid_sequence"] == 10
    assert "Sequence gap" in result["failure_reason"]


def test_verify_chain_deleted_event(ledger: LedgerEngine):
    """Test detection of deleted events."""
    ledger.append_event(
        event_type="event1",
        entity_id="entity1",
        payload={"seq": 1},
        actor="system",
    )
    
    event2 = ledger.append_event(
        event_type="event2",
        entity_id="entity2",
        payload={"seq": 2},
        actor="system",
    )
    
    ledger.append_event(
        event_type="event3",
        entity_id="entity3",
        payload={"seq": 3},
        actor="system",
    )
    
    # Delete the middle event
    ledger.db.execute(
        text(f"DELETE FROM ledger_events WHERE sequence = {event2.sequence}")
    )
    ledger.db.commit()
    
    result = ledger.verify_chain()
    assert result["valid"] is False
    assert "Sequence gap" in result["failure_reason"]


def test_verify_chain_inserted_event(ledger: LedgerEngine):
    """Test detection of inserted events by reordering."""
    ledger.append_event(
        event_type="event1",
        entity_id="entity1",
        payload={"seq": 1},
        actor="system",
    )
    
    event2 = ledger.append_event(
        event_type="event2",
        entity_id="entity2",
        payload={"seq": 2},
        actor="system",
    )
    
    # Simulate insertion by swapping sequence numbers to break the chain
    ledger.db.execute(
        text(f"UPDATE ledger_events SET sequence = 100 WHERE sequence = {event2.sequence}")
    )
    ledger.db.commit()
    
    result = ledger.verify_chain()
    # The verification will detect the sequence gap
    assert result["valid"] is False


def test_verify_chain_invalid_signature(ledger: LedgerEngine):
    """Test detection of invalid ECDSA signatures."""
    event = ledger.append_event(
        event_type="signed_event",
        entity_id="entity1",
        payload={"important": "data"},
        actor="system",
        sign=True,
    )
    
    # Corrupt the signature
    ledger.db.execute(
        text(f"UPDATE ledger_events SET signature = 'deadbeef' WHERE sequence = {event.sequence}")
    )
    ledger.db.commit()
    
    result = ledger.verify_chain()
    assert result["valid"] is False
    assert result["first_invalid_sequence"] == 0
    assert "Invalid signature" in result["failure_reason"]


def test_record_analyst_decision(ledger: LedgerEngine):
    """Test recording analyst decisions."""
    event = ledger.record_analyst_decision(
        entity_id="dataset_123",
        decision="ACCEPT",
        actor="analyst_jane",
        scan_id="scan_456",
        reason="No issues found",
    )
    
    assert event.event_type == "analyst_decision"
    assert event.entity_id == "dataset_123"
    assert event.actor == "analyst_jane"
    assert event.scan_id == "scan_456"
    assert event.signature is not None  # Should be signed


def test_invalid_analyst_decision(ledger: LedgerEngine):
    """Test that invalid decisions are recorded but validated at API level."""
    # The ledger engine records any decision string
    # Validation happens at the API layer
    event = ledger.record_analyst_decision(
        entity_id="dataset_123",
        decision="CUSTOM_DECISION",
        actor="analyst_jane",
    )
    assert event.event_type == "analyst_decision"
    # API validation would reject this in production


def test_get_events_by_scan(ledger: LedgerEngine):
    """Test retrieving events by scan ID."""
    ledger.append_event(
        event_type="scan_start",
        entity_id="scan_1",
        payload={"batch": "batch1"},
        actor="system",
        scan_id="scan_1",
    )
    
    ledger.append_event(
        event_type="finding",
        entity_id="dataset_1",
        payload={"severity": "HIGH"},
        actor="system",
        scan_id="scan_1",
    )
    
    ledger.append_event(
        event_type="other_event",
        entity_id="other",
        payload={"data": "test"},
        actor="system",
        scan_id="scan_2",
    )
    
    events = ledger.get_events_by_scan("scan_1")
    assert len(events) == 2
    assert all(e.scan_id == "scan_1" for e in events)


def test_get_events_by_entity(ledger: LedgerEngine):
    """Test retrieving events by entity ID."""
    ledger.append_event(
        event_type="event1",
        entity_id="entity_1",
        payload={"data": "test1"},
        actor="system",
    )
    
    ledger.append_event(
        event_type="event2",
        entity_id="entity_1",
        payload={"data": "test2"},
        actor="system",
    )
    
    ledger.append_event(
        event_type="event3",
        entity_id="entity_2",
        payload={"data": "test3"},
        actor="system",
    )
    
    events = ledger.get_events_by_entity("entity_1")
    assert len(events) == 2
    assert all(e.entity_id == "entity_1" for e in events)


def test_get_events_by_type(ledger: LedgerEngine):
    """Test retrieving events by type."""
    ledger.append_event(
        event_type="finding",
        entity_id="entity_1",
        payload={"severity": "HIGH"},
        actor="system",
    )
    
    ledger.append_event(
        event_type="finding",
        entity_id="entity_2",
        payload={"severity": "LOW"},
        actor="system",
    )
    
    ledger.append_event(
        event_type="ingestion",
        entity_id="entity_3",
        payload={"count": 10},
        actor="system",
    )
    
    events = ledger.get_events_by_type("finding")
    assert len(events) == 2
    assert all(e.event_type == "finding" for e in events)


def test_multiple_scans(ledger: LedgerEngine):
    """Test that ledger correctly handles events from multiple scans."""
    # Scan 1
    ledger.append_event(
        event_type="scan_start",
        entity_id="scan_1",
        payload={},
        actor="system",
        scan_id="scan_1",
    )
    ledger.append_event(
        event_type="finding",
        entity_id="dataset_1",
        payload={},
        actor="system",
        scan_id="scan_1",
    )
    
    # Scan 2
    ledger.append_event(
        event_type="scan_start",
        entity_id="scan_2",
        payload={},
        actor="system",
        scan_id="scan_2",
    )
    ledger.append_event(
        event_type="finding",
        entity_id="dataset_2",
        payload={},
        actor="system",
        scan_id="scan_2",
    )
    
    # Verify overall chain
    result = ledger.verify_chain()
    assert result["valid"] is True
    assert result["events_checked"] == 4
    
    # Verify per-scan retrieval
    scan1_events = ledger.get_events_by_scan("scan_1")
    scan2_events = ledger.get_events_by_scan("scan_2")
    assert len(scan1_events) == 2
    assert len(scan2_events) == 2