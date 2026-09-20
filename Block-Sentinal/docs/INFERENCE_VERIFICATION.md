# Inference Provenance Verification & Audit Protocol

This document defines the mathematical procedures, tamper-detection matrices, forensic evidence formats, and operational commands used to audit **Inference DNA Records** and **Inference Hash Chains**.

---

## 1. Single Record Verification Protocol

Verification of an individual `InferenceDNARecord` against a SubjectPublicKeyInfo PEM string executes in five sequential phases:

```
[ InferenceDNARecord ] + [ Public Key PEM ]
           |
           +---> 1. Recompute Canonical DNA Tuple Hash
           |        (using deterministic RFC 8785 canonical JSON)
           |
           +---> 2. Compare Recomputed Hash vs record.dna_hash
           |        [ FAIL: "DNA hash mismatch" ]
           |
           +---> 3. Verify Real ECDSA SECP256R1 Signature
           |        KeyManager.verify_signature(pubkey, record.dna_hash, record.signature)
           |        [ FAIL: "ECDSA signature invalid" ]
           |
           +---> 4. Validate Chain Pointer Format
           |        (Check length == 64 and hexadecimal characters)
           |        [ FAIL: "Invalid previous chain hash format" ]
           |
           +---> 5. Audit Field Alias Consistency
                    (Verify consistency between input_hash, input_frame_sha256, etc.)
                    [ FAIL: "Field alias discrepancy" ]
```

### Mathematical Verification Condition:
A record is valid if and only if:
$$\text{Verify}(R, K_{pub}) \iff \left( H(C(R)) = R.dna\_hash \right) \land \text{ECDSA\_Verify}(K_{pub}, R.dna\_hash, R.sig) \land \text{ValidPointer}(R.prev\_hash) \land \text{ConsistentAliases}(R)$$

---

## 2. Tamper-Detection Matrix

| Modification Vector | Affected Fields | Detection Mechanism | Result |
| :--- | :--- | :--- | :--- |
| **Input Tampering** | `input_hash`, `input_frame_sha256` | Canonical JSON re-hash mismatch | **FAIL** (`hash_integrity_valid = False`) |
| **Model Modification** | `model_hash`, `model_id`, `model_version` | Canonical JSON re-hash mismatch | **FAIL** (`hash_integrity_valid = False`) |
| **Preprocessing Modification** | `preprocessing_hash`, `preprocessing_digest` | Canonical JSON re-hash mismatch | **FAIL** (`hash_integrity_valid = False`) |
| **Config Modification** | `inference_config_hash` | Canonical JSON re-hash mismatch | **FAIL** (`hash_integrity_valid = False`) |
| **Output Tampering** | `output_hash`, `output_digest` | Canonical JSON re-hash mismatch | **FAIL** (`hash_integrity_valid = False`) |
| **Timestamp / Nonce Tampering** | `timestamp`, `nonce`, `sequence_number` | Canonical JSON re-hash mismatch | **FAIL** (`hash_integrity_valid = False`) |
| **Signature Forgery** | `signature` | SECP256R1 point scalar verification failure | **FAIL** (`signature_valid = False`) |
| **Pointer Tampering** | `prev_chain_hash` | Hexadecimal formatting check or chain gap | **FAIL** (`chain_pointer_valid = False`) |
| **Replay Attack** | `nonce`, `record_id` | Duplicate detection against persistent state journal | **FAIL** (`replay_detected = True`) |
| **Sequence Rollback** | `sequence_number` | Monotonicity check ($s_i \le s_{last}$) | **FAIL** (`sequence_rollback_detected = True`) |

---

## 3. Full Chain Verification Protocol

When verifying a stream of records $R = [r_1, r_2, \dots, r_n]$, `InferenceDNAVerifier.verify_chain()` enforces:

1. **Individual Cryptographic Integrity**: Every record $r_i$ must pass `verify_record(r_i, K_{pub})`.
2. **Freshness & Uniqueness (Anti-Replay)**:
   $$\forall i \ne j, \quad r_i.nonce \ne r_j.nonce \quad \land \quad r_i.record\_id \ne r_j.record\_id$$
3. **Sequence Monotonicity**:
   $$\forall i > 1, \quad r_i.sequence\_number = r_{i-1}.sequence\_number + 1$$
4. **Hash Pointer Continuity**:
   $$r_1.prev\_chain\_hash = 64 \times \text{'0'}$$
   $$\forall i > 1, \quad r_i.prev\_chain\_hash = r_{i-1}.dna\_hash$$

If any condition fails, the audit emits structured forensic evidence records:
- `INFERENCE_REPLAY_ATTACK`
- `SEQUENCE_CONTINUITY_BREAK`
- `BROKEN_HASH_CHAIN_POINTER`
- `SIGNATURE_OR_HASH_TAMPERING`

---

## 4. Verification Interfaces

### 4.1. Command-Line Interface (CLI)

#### Verify Single Record:
```bash
python -m app.cli verify-inference --file data/inference_dna/dna_0123456789abcdef.json --public-key-pem "$(cat certs/signing_pubkey.pem)"
```

#### Audit Full Chain from Directory:
```bash
python -m app.cli audit-inference-chain --dir data/inference_dna
```

### 4.2. REST API Endpoints

#### Verify Single Record (`POST /api/v1/inference/verify`):
```json
{
  "dna_record": { ... },
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\n..."
}
```
Response:
```json
{
  "success": true,
  "data": {
    "is_valid": true,
    "signature_valid": true,
    "hash_integrity_valid": true,
    "chain_pointer_valid": true,
    "replay_detected": false,
    "discrepancies": []
  }
}
```

#### Verify Complete Chain (`POST /api/v1/inference/verify-chain`):
```json
{
  "records": [ { ... }, { ... } ],
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\n..."
}
```
Response:
```json
{
  "success": true,
  "data": {
    "is_valid": true,
    "total_records": 2,
    "broken_sequence_id": null,
    "replay_detected": false,
    "discrepancies": [],
    "evidence_records": []
  }
}
```
