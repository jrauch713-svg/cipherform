"""Tests for the NaCl cryptographic service.

The crypto service is the foundation of CipherForm's zero-knowledge architecture.
These tests must be comprehensive — crypto bugs are catastrophic.
"""

import json

import pytest

from app.crypto.service import CryptoService


class TestKeyGeneration:
    """Tests for NaCl keypair generation."""

    def test_generate_keypair_returns_bytes(self):
        """Keypair generation should return bytes objects of correct lengths."""
        keypair = CryptoService.generate_keypair()

        assert isinstance(keypair.public_key, bytes)
        assert isinstance(keypair.private_key, bytes)
        assert len(keypair.public_key) == 32  # NaCl public key: 32 bytes
        assert len(keypair.private_key) == 32  # NaCl secret key: 32 bytes

    def test_generate_keypair_produces_unique_keys(self):
        """Each keypair should be unique."""
        kp1 = CryptoService.generate_keypair()
        kp2 = CryptoService.generate_keypair()

        assert kp1.public_key != kp2.public_key
        assert kp1.private_key != kp2.private_key

    def test_generate_keypair_encodes_to_base64(self):
        """Keypair should have base64-encoded representations."""
        keypair = CryptoService.generate_keypair()

        assert isinstance(keypair.public_key_b64, str)
        assert isinstance(keypair.private_key_b64, str)
        # Base64 of 32 bytes = 44 chars (with padding)
        assert len(keypair.public_key_b64) == 44


class TestEncryptDecrypt:
    """Tests for NaCl box encryption and decryption."""

    def test_encrypt_decrypt_roundtrip_json(self):
        """Encrypt a JSON payload and decrypt it — must roundtrip exactly."""
        form_keypair = CryptoService.generate_keypair()
        message = {"name": "Alice", "email": "alice@example.com", "message": "Hello"}

        encrypted = CryptoService.encrypt(message, form_keypair.public_key)
        decrypted = CryptoService.decrypt(encrypted, form_keypair.private_key)

        assert decrypted == message

    def test_encrypt_decrypt_roundtrip_plaintext(self):
        """Encrypt plaintext string and decrypt — must roundtrip."""
        form_keypair = CryptoService.generate_keypair()
        message = {"data": "plain text message with special chars: !@#$%"}

        encrypted = CryptoService.encrypt(message, form_keypair.public_key)
        decrypted = CryptoService.decrypt(encrypted, form_keypair.private_key)

        assert decrypted == message

    def test_encrypt_decrypt_roundtrip_unicode(self):
        """Encrypt and decrypt unicode content."""
        form_keypair = CryptoService.generate_keypair()
        message = {"name": "José", "city": "München", "emoji": "🔒"}

        encrypted = CryptoService.encrypt(message, form_keypair.public_key)
        decrypted = CryptoService.decrypt(encrypted, form_keypair.private_key)

        assert decrypted == message

    def test_encrypt_decrypt_roundtrip_large_payload(self):
        """Encrypt and decrypt a large payload (10KB)."""
        form_keypair = CryptoService.generate_keypair()
        message = {"data": "x" * 10000}

        encrypted = CryptoService.encrypt(message, form_keypair.public_key)
        decrypted = CryptoService.decrypt(encrypted, form_keypair.private_key)

        assert decrypted == message

    def test_encrypt_produces_different_ciphertexts(self):
        """Each encryption (even of same message) should produce different ciphertext."""
        form_keypair = CryptoService.generate_keypair()
        message = {"data": "same message"}

        enc1 = CryptoService.encrypt(message, form_keypair.public_key)
        enc2 = CryptoService.encrypt(message, form_keypair.public_key)

        # Different ciphertexts due to random nonce and ephemeral keys
        assert enc1.ciphertext != enc2.ciphertext

    def test_encrypt_returns_encrypted_payload_structure(self):
        """Encrypted payload must have required fields."""
        form_keypair = CryptoService.generate_keypair()
        message = {"data": "test"}

        encrypted = CryptoService.encrypt(message, form_keypair.public_key)

        assert isinstance(encrypted.ciphertext, bytes)
        assert isinstance(encrypted.nonce, bytes)
        assert isinstance(encrypted.ephemeral_public_key, bytes)
        assert len(encrypted.nonce) == 24  # NaCl nonce: 24 bytes
        assert len(encrypted.ephemeral_public_key) == 32


class TestDecryptionFailure:
    """Tests that decryption fails correctly in invalid scenarios."""

    def test_decrypt_with_wrong_private_key_fails(self):
        """Decrypting with the wrong private key must raise an error."""
        form_keypair = CryptoService.generate_keypair()
        other_keypair = CryptoService.generate_keypair()
        message = {"data": "secret"}

        encrypted = CryptoService.encrypt(message, form_keypair.public_key)

        with pytest.raises(CryptoService.DecryptionError):
            CryptoService.decrypt(encrypted, other_keypair.private_key)

    def test_decrypt_with_public_key_fails(self):
        """Server should not be able to decrypt with only the public key."""
        form_keypair = CryptoService.generate_keypair()
        message = {"data": "secret"}

        encrypted = CryptoService.encrypt(message, form_keypair.public_key)

        # Attempting decryption with public key (server's scenario) must fail
        with pytest.raises(CryptoService.DecryptionError):
            CryptoService.decrypt(encrypted, form_keypair.public_key)

    def test_decrypt_tampered_ciphertext_fails(self):
        """Tampered ciphertext must fail to decrypt."""
        form_keypair = CryptoService.generate_keypair()
        message = {"data": "secret"}

        encrypted = CryptoService.encrypt(message, form_keypair.public_key)

        # Tamper with the ciphertext
        tampered = bytearray(encrypted.ciphertext)
        tampered[0] ^= 0xFF  # flip bits

        encrypted.ciphertext = bytes(tampered)

        with pytest.raises(CryptoService.DecryptionError):
            CryptoService.decrypt(encrypted, form_keypair.private_key)


class TestKeySharing:
    """Tests for team key sharing via public-key re-encryption."""

    def test_encrypt_key_for_team_member(self):
        """Encrypt form private key for a team member, then decrypt it."""
        form_keypair = CryptoService.generate_keypair()
        member_keypair = CryptoService.generate_keypair()

        encrypted_key = CryptoService.encrypt_key_for_member(
            form_keypair.private_key, member_keypair.public_key
        )

        decrypted_key = CryptoService.decrypt_shared_key(
            encrypted_key, member_keypair.private_key
        )

        assert decrypted_key == form_keypair.private_key

    def test_shared_key_can_decrypt_responses(self):
        """After key sharing, team member can decrypt form responses."""
        form_keypair = CryptoService.generate_keypair()
        member_keypair = CryptoService.generate_keypair()
        message = {"data": "shared secret"}

        # Encrypt a response with the form's public key
        encrypted = CryptoService.encrypt(message, form_keypair.public_key)

        # Share the form's private key with the member
        encrypted_key = CryptoService.encrypt_key_for_member(
            form_keypair.private_key, member_keypair.public_key
        )

        # Member decrypts the shared key
        shared_private_key = CryptoService.decrypt_shared_key(
            encrypted_key, member_keypair.private_key
        )

        # Member uses shared key to decrypt response
        decrypted = CryptoService.decrypt(encrypted, shared_private_key)

        assert decrypted == message

    def test_wrong_member_cannot_decrypt_shared_key(self):
        """A non-intended member cannot decrypt the shared key."""
        form_keypair = CryptoService.generate_keypair()
        member_keypair = CryptoService.generate_keypair()
        attacker_keypair = CryptoService.generate_keypair()

        encrypted_key = CryptoService.encrypt_key_for_member(
            form_keypair.private_key, member_keypair.public_key
        )

        with pytest.raises(CryptoService.DecryptionError):
            CryptoService.decrypt_shared_key(encrypted_key, attacker_keypair.private_key)
