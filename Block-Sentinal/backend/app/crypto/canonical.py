"""Canonical serialization and deterministic cryptographic hashing."""
import hashlib
import json
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Dict


def _json_serial_default(obj: Any) -> str:
    """Serialize datetime and date objects to standard UTC ISO-8601 strings."""
    if isinstance(obj, (datetime, date)):
        if isinstance(obj, datetime) and obj.tzinfo is None:
            obj = obj.replace(tzinfo=timezone.utc)
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable to JSON")


def canonical_json_dumps(data: Dict[str, Any]) -> str:
    """Serialize dictionary to deterministic canonical JSON representation.
    
    Ensures keys are sorted, separators contain no extra whitespace,
    datetime objects are in ISO-8601 format, and characters are consistent UTF-8.
    """
    return json.dumps(
        data,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        default=_json_serial_default,
    )


def canonical_json_hash(data: Dict[str, Any]) -> str:
    """Return SHA-256 hexadecimal digest of canonical JSON serialized string."""
    canonical_str = canonical_json_dumps(data)
    return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()


def hash_bytes(data: bytes) -> str:
    """Return SHA-256 hexadecimal digest of raw byte sequence."""
    return hashlib.sha256(data).hexdigest()


def hash_file(filepath: str, chunk_size: int = 65536) -> str:
    """Stream a file from disk in chunks and return its SHA-256 hexadecimal digest.
    
    Raises FileNotFoundError if file is missing.
    """
    path = Path(filepath)
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {filepath}")

    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    return hasher.hexdigest()
