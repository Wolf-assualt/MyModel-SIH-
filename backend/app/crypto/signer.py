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


# Singleton instance for system-level signature generation
default_key_manager = KeyManager()
