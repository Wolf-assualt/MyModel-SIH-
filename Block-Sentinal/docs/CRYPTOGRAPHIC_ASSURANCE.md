# Cryptographic Assurance

## Overview

TRUST-CV uses standard cryptographic primitives for data integrity, digital signatures, and tamper-evidence. All cryptographic operations are performed using well-established libraries (cryptography.io) and follow industry best practices.

## Cryptographic Components

### Hashing

**Implementation:** `app/crypto/canonical.py`

**Algorithm:** SHA-256 (NIST FIPS 180-4)

**Functions:**
- `canonical_json_dumps(data)` - Deterministic JSON serialization
- `canonical_json_hash(data)` - SHA-256 hash of canonical JSON
- `hash_bytes(data)` - SHA-256 hash of raw bytes
- `hash_file(filepath)` - SHA-256 hash of file contents

**Usage:**
- Dataset manifest hashing
- Model artifact hashing
- Evidence payload hashing
- Ledger event payload hashing

**Limitations:**
- SHA-256 is considered secure for current applications but may need future migration to SHA-3 for long-term security
- No dedicated hardware acceleration (software-only implementation)

### Digital Signatures

**Implementation:** `app/crypto/signer.py`

**Algorithm:** ECDSA over SECP256R1 (NIST P-256)

**Key Management:**
- KeyManager class for ECDSA keypair management
- Keys generated using cryptography.io's ec.generate_private_key(ec.SECP256R1())
- Private keys exported in PKCS8 PEM format
- Public keys exported in SubjectPublicKeyInfo PEM format

**Functions:**
- `sign_hash(digest_hex: str) -> str` - Sign digest using ECDSA with SHA-256
- `verify_signature(public_key_pem, digest_hex, signature_hex) -> bool` - Verify ECDSA signature

**Usage:**
- Dataset manifest signing
- Model artifact signing
- Baseline profile signing
- Ledger analyst decision signing
- Evidence record signing

**Limitations:**
- Private keys kept in memory by default (not persisted)
- No hardware security module (HSM) integration
- Key rotation not automated
- Single keypair per system instance

### Merkle Trees

**Implementation:** `app/crypto/merkle.py`

**Algorithm:** SHA-256 based Merkle trees

**Functions:**
- Merkle tree construction from leaf hashes
- Merkle proof generation
- Merkle proof verification

**Usage:**
- Dataset sample integrity verification
- Batch manifest integrity verification

**Limitations:**
- Binary tree structure (no optimization for large datasets)
- No parallel tree construction

### Hash Chains

**Implementation:** `app/crypto/chain.py`

**Algorithm:** Sequential hash chaining with SHA-256

**Functions:**
- Hash chain construction
- Chain integrity verification

**Usage:**
- Inference DNA sequential verification
- Ledger event chain verification

**Limitations:**
- Linear verification time (O(n))
- No parallel verification

## Tamper-Evident Ledger

**Implementation:** `app/ledger/engine.py`

**Cryptographic Operations:**
- SHA-256 for event payload hashing (reuses `app/crypto.canonical`)
- ECDSA SECP256R1 for analyst decision signatures (reuses `app/crypto.signer`)
- Hash chain verification for tamper detection

**Event Structure:**
- Each event contains: sequence, timestamp, event_type, actor, scan_id, entity_id, payload_hash, previous_hash, current_hash, signature
- current_hash = SHA256(sequence + timestamp + event_type + actor + scan_id + entity_id + payload_hash + previous_hash)
- previous_hash links to previous event's current_hash

**Tamper Detection:**
- Modified event data (hash recomputation fails)
- Modified payload hash (hash recomputation fails)
- Broken previous_hash linkage (chain continuity broken)
- Sequence gaps (missing events)
- Invalid ECDSA signatures (signature verification fails)

**Limitations:**
- SQLite database for storage (file system access required)
- No built-in key persistence
- Single-writer design (no concurrent write support)

## Security Considerations

### Key Management

**Current State:**
- System ECDSA keypair generated on first use
- Private keys kept in memory only
- No automatic key rotation
- No hardware security module integration

**Recommendations:**
- Implement secure key storage (e.g., encrypted key files, HSM)
- Implement key rotation policy
- Backup private keys securely
- Never commit private keys to version control

### Algorithm Selection

**Current Algorithms:**
- SHA-256 for hashing
- ECDSA SECP256R1 for signatures

**Rationale:**
- Well-established, widely-reviewed algorithms
- Supported by standard cryptography libraries
- Sufficient for current threat model

**Future Considerations:**
- Monitor NIST recommendations for post-quantum migration
- Consider SHA-3 for future hashing needs
- Evaluate Ed25519 for signature performance improvements

### Implementation Security

**Current Practices:**
- Uses cryptography.io library (well-maintained, audited)
- Constant-time operations where applicable
- No side-channel mitigations beyond library defaults
- No custom cryptographic implementations

**Limitations:**
- No formal verification of cryptographic code
- No dedicated security audit
- Limited side-channel resistance testing

## Compliance and Standards

**Standards Followed:**
- NIST FIPS 180-4 (SHA-256)
- NIST FIPS 186-4 (ECDSA)
- RFC 5480 (SubjectPublicKeyInfo format)
- RFC 5958 (PKCS8 format)

**Regulatory Considerations:**
- Not FIPS 140-2 validated (uses cryptography.io, not FIPS module)
- Suitable for general security applications
- Consult compliance requirements for regulated environments

## Performance Characteristics

**Hashing:**
- SHA-256: ~100 MB/s on modern CPUs (software implementation)
- No hardware acceleration

**Signatures:**
- ECDSA SECP256R1 signing: ~1-5 ms per operation
- ECDSA SECP256R1 verification: ~2-10 ms per operation
- Performance varies by CPU and implementation

**Scalability:**
- Suitable for typical CV dataset sizes (thousands to millions of samples)
- Linear verification time for hash chains
- Consider batching for large-scale operations

## Known Limitations

1. **No Hardware Acceleration:** All cryptographic operations are software-only
2. **No Quantum Resistance:** Algorithms are not post-quantum secure
3. **Limited Key Management:** No automated key rotation or HSM integration
4. **Single Writer Ledger:** No concurrent write support for ledger
5. **Memory-Based Keys:** Private keys not persisted by default
6. **No Formal Verification:** Cryptographic code not formally verified
7. **Library Dependencies:** Relies on cryptography.io for implementation correctness

## References

- cryptography.io: https://cryptography.io/
- NIST Cryptographic Standards: https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines
- FIPS 180-4 (SHA-256): https://csrc.nist.gov/publications/detail/fips/180/4/final
- FIPS 186-4 (ECDSA): https://csrc.nist.gov/publications/detail/fips/186/4/final