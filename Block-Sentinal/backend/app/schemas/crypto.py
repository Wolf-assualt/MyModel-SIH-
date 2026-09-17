"""Pydantic schemas for cryptographic operations."""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class HashRequest(BaseModel):
    data: Dict[str, Any]


class HashResponse(BaseModel):
    canonical_hash: str = Field(..., min_length=64, max_length=64)


class MerkleBuildRequest(BaseModel):
    leaves: List[str]


class MerkleBuildResponse(BaseModel):
    root: str
    leaf_count: int


class MerkleVerifyRequest(BaseModel):
    leaf: str
    proof: List[Dict[str, Any]]
    root: str


class VerifyResponse(BaseModel):
    valid: bool
    details: Optional[str] = None


class SignRequest(BaseModel):
    digest: str = Field(..., min_length=1)


class SignResponse(BaseModel):
    signature: str
    public_key_pem: str


class VerifySignatureRequest(BaseModel):
    digest: str
    signature: str
    public_key_pem: str


class ChainAppendRequest(BaseModel):
    data_hash: str = Field(..., min_length=64, max_length=64)


class ChainVerifyRequest(BaseModel):
    records: List[Dict[str, Any]]


class ChainVerifyResponse(BaseModel):
    valid: bool
    broken_index: Optional[int] = None
    message: str
