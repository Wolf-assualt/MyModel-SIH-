"""Test ledger persistence across restarts."""
import pytest
import tempfile
import shutil
from pathlib import Path
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session

from app.ledger.engine import LedgerEngine
from app.ledger.database import LedgerBase
from app.models.ledger import LedgerEvent
from app.crypto.signer import KeyManager


@pytest.fixture(scope="function")
def temp_ledger_dir():
    """Create a temporary directory for the ledger database."""
    temp_dir = tempfile.mkdtemp()
    ledger_path = Path(temp_dir) / "ledger.db"
    yield str(ledger_path)
    shutil.rmtree(temp_dir, ignore_errors=True)


def test_ledger_persistence_append_restart_verify(temp_ledger_dir):
    """Test that ledger persists across restarts and verification works."""
    ledger_url = f"sqlite:///{temp_ledger_dir}"
    
    # Create engine and session for first run
    engine = create_engine(ledger_url, connect_args={"check_same_thread": False})
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    LedgerBase.metadata.create_all(bind=engine)
    
    # First run: append events
    key_manager = KeyManager()
    db1 = SessionLocal()
    ledger1 = LedgerEngine(db1, key_manager=key_manager)
    
    event1 = ledger1.append_event(
        event_type="ingestion",
        entity_id="batch_1",
        payload={"sample_count": 10},
        actor="system",
        scan_id="scan_1",
    )
    
    event2 = ledger1.append_event(
        event_type="finding",
        entity_id="batch_1",
        payload={"severity": "HIGH"},
        actor="system",
        scan_id="scan_1",
    )
    
    event3 = ledger1.append_event(
        event_type="scan_complete",
        entity_id="scan_1",
        payload={"disposition": "ACCEPTED"},
        actor="system",
        scan_id="scan_1",
    )
    
    db1.commit()
    db1.close()
    
    # Simulate restart: create new engine and session
    engine2 = create_engine(ledger_url, connect_args={"check_same_thread": False})
    SessionLocal2 = sessionmaker(autocommit=False, autoflush=False, bind=engine2)
    
    # Second run: reopen and verify
    db2 = SessionLocal2()
    ledger2 = LedgerEngine(db2, key_manager=key_manager)
    
    # Verify the chain is intact
    verification_result = ledger2.verify_chain()
    assert verification_result["valid"] is True
    assert verification_result["events_checked"] == 3
    assert verification_result["last_verified_sequence"] == 2
    
    # Verify we can retrieve the events
    events = ledger2.get_events_by_scan("scan_1")
    assert len(events) == 3
    assert events[0].event_type == "ingestion"
    assert events[1].event_type == "finding"
    assert events[2].event_type == "scan_complete"
    
    # Verify hash chain linkage
    assert events[1].previous_hash == events[0].current_hash
    assert events[2].previous_hash == events[1].current_hash
    
    db2.close()


def test_ledger_persistence_with_signature(temp_ledger_dir):
    """Test that signed events persist correctly across restarts."""
    ledger_url = f"sqlite:///{temp_ledger_dir}"
    
    # First run: append signed event
    engine = create_engine(ledger_url, connect_args={"check_same_thread": False})
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    LedgerBase.metadata.create_all(bind=engine)
    
    key_manager = KeyManager()
    private_key_pem = key_manager.export_private_key_pem()
    public_key_pem = key_manager.export_public_key_pem()
    
    db1 = SessionLocal()
    ledger1 = LedgerEngine(db1, key_manager=key_manager)
    
    signed_event = ledger1.append_event(
        event_type="analyst_decision",
        entity_id="batch_1",
        payload={"decision": "ACCEPT"},
        actor="analyst_jane",
        sign=True,
    )
    
    db1.commit()
    db1.close()
    
    # Second run: reopen and verify signature
    engine2 = create_engine(ledger_url, connect_args={"check_same_thread": False})
    SessionLocal2 = sessionmaker(autocommit=False, autoflush=False, bind=engine2)
    
    # Reconstruct the same key manager from the saved private key
    key_manager2 = KeyManager(private_key_pem=private_key_pem)
    db2 = SessionLocal2()
    ledger2 = LedgerEngine(db2, key_manager=key_manager2)
    
    # Verify the chain including signature
    verification_result = ledger2.verify_chain()
    assert verification_result["valid"] is True
    assert verification_result["events_checked"] == 1
    
    # Retrieve and verify the signed event
    events = ledger2.get_events_by_entity("batch_1")
    assert len(events) == 1
    assert events[0].signature is not None
    
    # Verify signature is still valid
    assert KeyManager.verify_signature(
        public_key_pem,
        events[0].current_hash,
        events[0].signature
    )
    
    db2.close()


def test_ledger_persistence_tamper_detection(temp_ledger_dir):
    """Test that tampering is detected after restart."""
    ledger_url = f"sqlite:///{temp_ledger_dir}"
    
    # First run: append events
    engine = create_engine(ledger_url, connect_args={"check_same_thread": False})
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    LedgerBase.metadata.create_all(bind=engine)
    
    key_manager = KeyManager()
    db1 = SessionLocal()
    ledger1 = LedgerEngine(db1, key_manager=key_manager)
    
    event1 = ledger1.append_event(
        event_type="ingestion",
        entity_id="batch_1",
        payload={"sample_count": 10},
        actor="system",
    )
    
    db1.commit()
    db1.close()
    
    # Tamper with the database directly
    engine_tamper = create_engine(ledger_url, connect_args={"check_same_thread": False})
    SessionLocalTamper = sessionmaker(autocommit=False, autoflush=False, bind=engine_tamper)
    db_tamper = SessionLocalTamper()
    db_tamper.execute(text("UPDATE ledger_events SET entity_id = 'tampered' WHERE sequence = 0"))
    db_tamper.commit()
    db_tamper.close()
    
    # Second run: reopen and verify - should detect tampering
    engine2 = create_engine(ledger_url, connect_args={"check_same_thread": False})
    SessionLocal2 = sessionmaker(autocommit=False, autoflush=False, bind=engine2)
    
    db2 = SessionLocal2()
    ledger2 = LedgerEngine(db2, key_manager=key_manager)
    
    verification_result = ledger2.verify_chain()
    assert verification_result["valid"] is False
    assert "Current hash recomputation failed" in verification_result["failure_reason"]
    assert verification_result["first_invalid_sequence"] == 0
    
    db2.close()