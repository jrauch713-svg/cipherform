"""NaCl cryptographic service for zero-knowledge form encryption.

All encryption and decryption uses NaCl box (Curve25519 + XSalsa20-Poly1305).
Private keys are NEVER stored or processed server-side — this module exists
for client-side use and testing. The server only stores ciphertext blobs.
"""

import json
from base64 import b64decode, b64encode
from dataclasses import dataclass
from typing import Any

from nacl.exceptions import CryptoError
from nacl.public import Box, PrivateKey, PublicKey
from nacl.utils import random


class CryptoService:
    """NaCl cryptographic operations for CipherForm.

    All methods are static — no state, no key storage.
    """

    class DecryptionError(Exception):
        """Raised when decryption fails (wrong key, tampered data, etc.)."""
        pass

    @dataclass(frozen=True)
    class Keypair:
        """A NaCl keypair with raw bytes and base64 representations."""
        public_key: bytes
        private_key: bytes

        @property
        def public_key_b64(self) -> str:
            return b64encode(self.public_key).decode("ascii")

        @property
        def private_key_b64(self) -> str:
            return b64encode(self.private_key).decode("ascii")

    @dataclass
    class EncryptedPayload:
        """An encrypted message with all metadata needed for decryption."""
        ciphertext: bytes
        nonce: bytes
        ephemeral_public_key: bytes

    @staticmethod
    def generate_keypair() -> "CryptoService.Keypair":
        """Generate a new NaCl keypair for form encryption.

        Returns:
            Keypair with 32-byte public and private keys.
        """
        private_key = PrivateKey.generate()
        public_key = private_key.public_key

        return CryptoService.Keypair(
            public_key=bytes(public_key),
            private_key=bytes(private_key),
        )

    @staticmethod
    def encrypt(data: dict[str, Any], recipient_public_key: bytes) -> "CryptoService.EncryptedPayload":
        """Encrypt a JSON-serializable dict for a recipient.

        Uses NaCl box with an ephemeral keypair for forward secrecy.
        Each encryption produces different ciphertext (random nonce + ephemeral key).

        Args:
            data: JSON-serializable dict to encrypt.
            recipient_public_key: Recipient's 32-byte NaCl public key.

        Returns:
            EncryptedPayload with ciphertext, nonce, and ephemeral public key.
        """
        plaintext = json.dumps(data).encode("utf-8")
        recipient_pk = PublicKey(recipient_public_key)

        # Ephemeral keypair for forward secrecy
        ephemeral_sk = PrivateKey.generate()
        box = Box(ephemeral_sk, recipient_pk)

        nonce = random(Box.NONCE_SIZE)
        ciphertext = box.encrypt(plaintext, nonce)

        # nacl box.encrypt prepends the nonce; we strip it for separate storage
        actual_nonce = ciphertext[: Box.NONCE_SIZE]
        actual_ciphertext = ciphertext[Box.NONCE_SIZE :]

        return CryptoService.EncryptedPayload(
            ciphertext=actual_ciphertext,
            nonce=actual_nonce,
            ephemeral_public_key=bytes(ephemeral_sk.public_key),
        )

    @staticmethod
    def decrypt(payload: "CryptoService.EncryptedPayload", recipient_private_key: bytes) -> dict[str, Any]:
        """Decrypt an encrypted payload.

        Args:
            payload: EncryptedPayload with ciphertext, nonce, and ephemeral public key.
            recipient_private_key: Recipient's 32-byte NaCl private key.

        Returns:
            The original dict that was encrypted.

        Raises:
            DecryptionError: If decryption fails for any reason (wrong key,
                tampered data, invalid format).
        """
        try:
            recipient_sk = PrivateKey(recipient_private_key)
            ephemeral_pk = PublicKey(payload.ephemeral_public_key)
            box = Box(recipient_sk, ephemeral_pk)

            # Reconstruct the nacl-format ciphertext (nonce + ciphertext)
            combined = payload.nonce + payload.ciphertext
            plaintext = box.decrypt(combined)
            return json.loads(plaintext.decode("utf-8"))
        except (CryptoError, json.JSONDecodeError, UnicodeDecodeError, ValueError) as e:
            raise CryptoService.DecryptionError(f"Decryption failed: {e}") from e

    @staticmethod
    def encrypt_key_for_member(
        form_private_key: bytes, member_public_key: bytes
    ) -> "CryptoService.EncryptedPayload":
        """Encrypt a form's private key for sharing with a team member.

        Uses the same NaCl box mechanism as message encryption.

        Args:
            form_private_key: The form's 32-byte NaCl private key.
            member_public_key: Team member's 32-byte NaCl public key.

        Returns:
            EncryptedPayload containing the encrypted private key.
        """
        data = {"form_private_key": b64encode(form_private_key).decode("ascii")}
        return CryptoService.encrypt(data, member_public_key)

    @staticmethod
    def decrypt_shared_key(
        payload: "CryptoService.EncryptedPayload", member_private_key: bytes
    ) -> bytes:
        """Decrypt a shared form private key.

        Args:
            payload: EncryptedPayload from encrypt_key_for_member.
            member_private_key: Team member's 32-byte NaCl private key.

        Returns:
            The form's 32-byte NaCl private key.

        Raises:
            DecryptionError: If decryption fails (wrong member, tampered).
        """
        try:
            data = CryptoService.decrypt(payload, member_private_key)
            return b64decode(data["form_private_key"])
        except (KeyError, ValueError) as e:
            raise CryptoService.DecryptionError(f"Failed to extract shared key: {e}") from e
