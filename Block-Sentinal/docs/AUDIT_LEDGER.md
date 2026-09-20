# Tamper-Evident Assurance Ledger

## Overview

The Tamper-Evident Assurance Ledger provides persistent, cryptographically secure audit logging for all security events in the TRUST-CV system. It uses SQLite for local storage and hash-chain verification to detect any tampering with historical records.

## Architecture

### Components

- **LedgerEngine** (`app/ledger/engine.py`): Core engine for appending events and verifying chain integrity
- **LedgerEvent** (`app/models/ledger.py`): SQLAlchemy model for ledger events
- **Ledger Database** (`app/ledger/database.py`): SQLite database configuration

### Event Structure

Each ledger event contains:
- `sequence`: Monotonically increasing sequence number
- `timestamp`: UTC timestamp of event creation
- `event_type`: Type of event (ingestion, finding, model_verification, etc.)
- `actor`: System or user who initiated the event
- `scan_id`: Associated scan session ID (if applicable)
- `entity_id`: ID of the entity being acted upon
- `payload_hash`: SHA-256 hash of the event payload
- `previous_hash`: Hash of the previous event in the chain
- `current_hash`: Hash of this event (chain link)
- `signature`: ECDSA signature (for signed events like analyst decisions)

### Event Types

The ledger records the following event types:
- `scan_start`: Initiation of a scan session
- `ingestion`: Dataset ingestion and hashing
- `finding`: Security findings from integrity analysis
- `model_verification`: Model identity verification
- `inference`: Model inference execution
- `drift_assessment`: Distribution shift analysis
- `evidence_fusion`: Evidence fusion assessment
- `evidence_graph`: Evidence graph construction
- `scan_complete`: Scan session completion
- `analyst_decision`: Human analyst decisions (ACCEPT, REVIEW, QUARANTINE)

## Hash Chain Verification

The ledger uses a hash chain to ensure tamper-evidence:

1. Each event's `current_hash` is computed from: sequence, timestamp, event_type, actor, scan_id, entity_id, payload_hash, and previous_hash
2. Each event's `previous_hash` points to the previous event's `current_hash`
3. The first event has `previous_hash` = "0" * 64
4. Verification recomputes each hash and checks chain continuity

### Tamper Detection

The verification process detects:
- Modified event data (hash recomputation fails)
- Modified payload hash (hash recomputation fails)
- Broken previous_hash linkage (chain continuity broken)
- Sequence gaps (missing events)
- Invalid ECDSA signatures (signature verification fails)
- Deleted events (sequence gaps)
- Inserted events (sequence gaps or hash mismatches)

## Cryptographic Operations

### Hashing

- Uses SHA-256 for all hashing operations
- Canonical JSON serialization for deterministic payload hashing
- Reuses existing `app.crypto.canonical` module

### Signatures

- Uses ECDSA (SECP256R1) for signing critical events
- Analyst decisions are always signed
- Reuses existing `app.crypto.signer` module
- Signatures are verified during chain verification

## Persistence

### Storage

- SQLite database stored at `./data/ledger/ledger.db`
- Separate from main application database
- Configured via `LEDGER_SQLITE_URL` in settings

### Key Management

- System ECDSA keypair generated on first use
- Private key kept in memory (not persisted)
- For persistence across restarts, private key must be externally managed
- Public key used for signature verification

## API Endpoints

### Verification

```
GET /api/v1/ledger/verify
```

Returns verification results:
- `valid`: Whether the chain is valid
- `events_checked`: Number of events checked
- `last_verified_sequence`: Last sequence number verified
- `first_invalid_sequence`: First invalid sequence if failed
- `failure_reason`: Reason for failure

### Event Queries

```
GET /api/v1/ledger/events
GET /api/v1/ledger/events/scan/{scan_id}
GET /api/v1/ledger/events/entity/{entity_id}
GET /api/v1/ledger/events/type/{event_type}
```

### Analyst Decisions

```
POST /api/v1/ledger/decision
```

Records cryptographically signed analyst decisions:
- `entity_id`: Target entity
- `decision`: ACCEPT, REVIEW, or QUARANTINE
- `actor`: Analyst identifier
- `scan_id`: Optional associated scan
- `reason`: Optional decision reason

## Integration with Scan Pipeline

The ledger is integrated into the scan pipeline in `app/api/scan.py`:

1. **Scan Start**: Records scan initiation
2. **Ingestion**: Records dataset ingestion with sample count and merkle root
3. **Findings**: Records each security finding with severity and description
4. **Model Verification**: Records model identity verification results
5. **Inference**: Records model inference execution
6. **Drift Assessment**: Records distribution shift analysis results
7. **Evidence Fusion**: Records fusion assessment results
8. **Evidence Graph**: Records graph construction
9. **Scan Complete**: Records final disposition and assurance score

All ledger operations are wrapped in try-catch blocks to prevent ledger failures from blocking the scan pipeline.

## Limitations

1. **Key Persistence**: The system ECDSA keypair is not persisted by default. For production use, implement secure key storage and loading.

2. **Single Writer**: The ledger is designed for single-writer scenarios. Concurrent writes may cause sequence conflicts.

3. **Database Size**: SQLite has practical limits on database size. For very high-volume deployments, consider migrating to PostgreSQL.

4. **No Pruning**: The ledger does not automatically prune old events. Implement retention policies if needed.

5. **Offline Operation**: The ledger is designed for offline/air-gapped operation. No external dependencies or network calls.

## Security Considerations

1. **Database Access**: The ledger database file should have appropriate file system permissions.

2. **Key Management**: Private keys must be protected. Never commit private keys to version control.

3. **Backup Strategy**: Implement regular backups of the ledger database with cryptographic verification.

4. **Verification on Startup**: The ledger should be verified on application startup to detect any tampering.

5. **Compromised Ledger**: If verification fails, the ledger should be marked as compromised and not used for security decisions.

## Testing

Comprehensive tests are provided in:
- `tests/test_ledger.py`: Core ledger functionality tests
- `tests/test_ledger_persistence.py`: Persistence and restart tests

Test coverage includes:
- Event appending and sequence continuity
- Hash chain verification
- Tamper detection (modified events, broken chains, etc.)
- Signature verification
- Persistence across restarts
- Query operations
- Multiple scan handling