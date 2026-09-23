"""ECDSA (SECP256R1) Key Management, Digital Signatures, and Verification."""
from typing import Optional
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


class KeyManager:
    """Manages ECDSA SECP256R1 asymmetric keypairs for signing digests and evidence records."""

    def __init__(self, private_key_pem: Optional[bytes] = None):
        if private_key_pem:
            self.private_key = serialization.load_pem_private_key(private_key_pem, password=None)
        else:
            self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()

    def export_private_key_pem(self) -> bytes:
        """Export private key in PKCS8 PEM format."""
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def export_public_key_pem(self) -> bytes:
        """Export public key in SubjectPublicKeyInfo PEM format."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def sign_hash(self, digest_hex: str) -> str:
        """Sign a digest using ECDSA with SHA-256 and return the hex-encoded signature."""
        signature_bytes = self.private_key.sign(
            digest_hex.encode("utf-8"),
            ec.ECDSA(hashes.SHA256()),
        )
        return signature_bytes.hex()

    @staticmethod
    def verify_signature(public_key_pem: bytes, digest_hex: str, signature_hex: str) -> bool:
        """Verify an ECDSA signature against the provided public key PEM."""
        try:
            if isinstance(public_key_pem, str):
                public_key_pem = public_key_pem.encode("utf-8")
            pubkey = serialization.load_pem_public_key(public_key_pem)
            sig_bytes = bytes.fromhex(signature_hex)
            pubkey.verify(
                sig_bytes,
                digest_hex.encode("utf-8"),
                ec.ECDSA(hashes.SHA256()),
            )
            return True
        except (InvalidSignature, ValueError, TypeError):
            return False


def get_or_create_persistent_key_manager() -> KeyManager:
    """Load or generate a persistent system KeyManager so signatures survive process restarts."""
    import os
    from pathlib import Path
    try:
        from app.core.config import settings
        keys_dir = Path(settings.DATA_DIR) / "keys"
    except Exception:
        keys_dir = Path("./data/keys")
    
    keys_dir.mkdir(parents=True, exist_ok=True)
    priv_key_file = keys_dir / "system_private_key.pem"

    if priv_key_file.exists():
        try:
            pem_bytes = priv_key_file.read_bytes()
            return KeyManager(private_key_pem=pem_bytes)
        except Exception:
            pass

    km = KeyManager()
    try:
        priv_key_file.write_bytes(km.export_private_key_pem())
    except Exception:
        pass
    return km


# Singleton instance for system-level signature generation (persisted across restarts)
default_key_manager = get_or_create_persistent_key_manager()
default_signer = default_key_manager
Signer = KeyManager

