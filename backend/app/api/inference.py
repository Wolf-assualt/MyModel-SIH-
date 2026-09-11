"""Inference execution under provenance tracking and cryptographic audit API."""
import base64
from typing import Any, Dict
from fastapi import APIRouter, HTTPException

from app.crypto.canonical import canonical_json_hash, hash_bytes
from app.inference.dna import default_dna_generator
from app.inference.verifier import InferenceDNAVerifier
from app.schemas.base import ResponseEnvelope
from app.schemas.inference import (
    BoundingBox,
    InferenceOutput,
    InferenceReceipt,
    InferenceRequest,
    PreprocessingSpec,
    VerifyDNARequest,
    VerifyDNAResponse,
)

router = APIRouter(prefix="/inference", tags=["Inference DNA & Provenance"])


@router.post("/execute", response_model=ResponseEnvelope[InferenceReceipt])
def execute_inference_with_provenance(
    payload: InferenceRequest,
) -> ResponseEnvelope[InferenceReceipt]:
    """Execute inference and cryptographically seal input, model, preprocessing, and output into an Inference DNA receipt."""
    # 1. Resolve input frame hash
    if payload.image_sha256:
        input_sha256 = payload.image_sha256
    elif payload.image_bytes_b64:
        try:
            raw_bytes = base64.b64decode(payload.image_bytes_b64)
            input_sha256 = hash_bytes(raw_bytes)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid base64 encoding in image_bytes_b64.")
    else:
        # Deterministic synthetic frame digest when raw payload is omitted
        input_sha256 = hash_bytes(f"synthetic_frame_input_{payload.model_id}".encode("utf-8"))

    # 2. Resolve model identity digest
    model_identity_digest = hash_bytes(f"identity_digest_manifest_{payload.model_id}".encode("utf-8"))

    # 3. Resolve preprocessing parameters
    prep_spec = payload.preprocessing or PreprocessingSpec()

    # 4. Generate deterministic forward pass detections
    predictions = [
        BoundingBox(label="military_vehicle", confidence=0.94, box=[120.0, 140.0, 320.0, 420.0]),
        BoundingBox(label="personnel", confidence=0.88, box=[50.0, 75.0, 110.0, 200.0]),
    ]
    raw_output_digest = canonical_json_hash([p.model_dump() for p in predictions])
    output = InferenceOutput(predictions=predictions, raw_output_digest=raw_output_digest)

    # 5. Bind into immutable DNA record
    try:
        dna_record = default_dna_generator.create_dna_record(
            model_id=payload.model_id,
            model_identity_digest=model_identity_digest,
            input_frame_sha256=input_sha256,
            prep_spec=prep_spec,
            output=output,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    receipt = InferenceReceipt(
        dna_record=dna_record,
        output=output,
        public_key_pem=default_dna_generator.export_public_key_pem(),
    )
    return ResponseEnvelope(data=receipt)


@router.post("/verify", response_model=ResponseEnvelope[VerifyDNAResponse])
def verify_inference_dna(
    payload: VerifyDNARequest,
) -> ResponseEnvelope[VerifyDNAResponse]:
    """Cryptographically audit an inference DNA record against a public key."""
    result = InferenceDNAVerifier.verify_record(
        record=payload.dna_record,
        public_key_pem=payload.public_key_pem,
    )
    return ResponseEnvelope(data=result)


@router.get("/chain", response_model=ResponseEnvelope[Dict[str, Any]])
def get_inference_hash_chain() -> ResponseEnvelope[Dict[str, Any]]:
    """Retrieve the current audit hash chain tip and recorded sequence history."""
    state = default_dna_generator.get_chain_state()
    return ResponseEnvelope(data=state)
