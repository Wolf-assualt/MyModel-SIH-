"""Ed25519 Key Management, Digital Signatures, and Verification."""
from typing import Optional, Union
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


class KeyManager:
    """Manages Ed25519 asymmetric keypairs for signing digests and evidence records."""

    def __init__(self, private_key_pem: Optional[bytes] = None):
        if private_key_pem:
            loaded_key = serialization.load_pem_private_key(private_key_pem, password=None)
            if not isinstance(loaded_key, ed25519.Ed25519PrivateKey):
                raise ValueError("Provided key is not an Ed25519 private key")
            self.private_key = loaded_key
        else:
            self.private_key = ed25519.Ed25519PrivateKey.generate()
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

    def sign_hash(self, digest_hex: Union[str, bytes]) -> str:
        """Sign a digest using Ed25519 and return the hex-encoded signature."""
        if isinstance(digest_hex, str):
            data = digest_hex.encode("utf-8")
        else:
            data = digest_hex
        signature_bytes = self.private_key.sign(data)
        return signature_bytes.hex()

    @staticmethod
    def verify_signature(
        public_key_pem: Union[bytes, str],
        digest_hex: Union[str, bytes],
        signature_hex: str,
    ) -> bool:
        """Verify an Ed25519 signature against the provided public key PEM."""
        try:
            if isinstance(public_key_pem, str):
                public_key_pem = public_key_pem.encode("utf-8")
            pubkey = serialization.load_pem_public_key(public_key_pem)
            if not isinstance(pubkey, ed25519.Ed25519PublicKey):
                return False
            sig_bytes = bytes.fromhex(signature_hex)
            if isinstance(digest_hex, str):
                data = digest_hex.encode("utf-8")
            else:
                data = digest_hex
            pubkey.verify(sig_bytes, data)
            return True
        except (InvalidSignature, ValueError, TypeError, Exception):
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
            km = KeyManager(private_key_pem=pem_bytes)
            return km
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


