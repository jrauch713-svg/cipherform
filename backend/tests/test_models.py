"""Tests for database models."""

from datetime import datetime, timezone
from uuid import uuid4

import pytest


class TestUserModel:
    """Tests for the User database model."""

    def test_user_creation(self):
        """User model should be creatable with required fields."""
        from app.models.user import User

        user = User(
            email="test@example.com",
            password_hash="$2b$12$hashedpassword",
            public_key="base64publickey",
        )

        assert user.email == "test@example.com"
        assert user.password_hash == "$2b$12$hashedpassword"
        assert user.public_key == "base64publickey"
        assert user.tier == "starter"
        assert isinstance(user.id, str)
        assert len(user.id) == 36  # UUID string length

    def test_user_default_tier(self):
        """New users should default to starter tier."""
        from app.models.user import User

        user = User(
            email="new@example.com",
            password_hash="hash",
            public_key="pk",
        )

        assert user.tier == "starter"

    def test_user_custom_tier(self):
        """Users can be created with a non-default tier."""
        from app.models.user import User

        user = User(
            email="pro@example.com",
            password_hash="hash",
            public_key="pk",
            tier="pro",
        )

        assert user.tier == "pro"

    def test_user_created_at_is_set(self):
        """User should have created_at set on creation."""
        from app.models.user import User

        user = User(
            email="time@example.com",
            password_hash="hash",
            public_key="pk",
        )

        assert user.created_at is not None
        assert isinstance(user.created_at, datetime)

    def test_user_stripe_customer_id_optional(self):
        """stripe_customer_id should be optional (None by default)."""
        from app.models.user import User

        user = User(
            email="nostripe@example.com",
            password_hash="hash",
            public_key="pk",
        )

        assert user.stripe_customer_id is None


class TestFormModel:
    """Tests for the Form database model."""

    def test_form_creation(self):
        """Form model should be creatable with required fields."""
        from app.models.form import Form

        form = Form(
            user_id=uuid4(),
            title="Client Intake Form",
            description="New client information",
            public_key="base64formpublickey",
            fields=[],
        )

        assert form.title == "Client Intake Form"
        assert form.description == "New client information"
        assert form.public_key == "base64formpublickey"
        assert form.fields == []
        assert form.response_count == 0
        assert form.is_active is True

    def test_form_defaults(self):
        """Form should have sensible defaults."""
        from app.models.form import Form

        form = Form(
            user_id=uuid4(),
            title="Test",
            public_key="pk",
        )

        assert form.fields == []
        assert form.settings == {}
        assert form.response_count == 0
        assert form.is_active is True

    def test_form_with_fields(self):
        """Form should store field definitions as JSON."""
        from app.models.form import Form

        fields = [
            {"name": "full_name", "type": "text", "required": True},
            {"name": "email", "type": "email", "required": True},
            {"name": "message", "type": "textarea", "required": False},
        ]

        form = Form(
            user_id=uuid4(),
            title="Contact Form",
            public_key="pk",
            fields=fields,
        )

        assert len(form.fields) == 3
        assert form.fields[0]["name"] == "full_name"
        assert form.fields[0]["type"] == "text"


class TestResponseModel:
    """Tests for the Response database model."""

    def test_response_creation(self):
        """Response model should store encrypted blobs."""
        from app.models.response import Response

        response = Response(
            form_id=uuid4(),
            ciphertext=b"encrypted_data_here",
            nonce=b"\x00" * 24,
            ephemeral_public_key=b"\x00" * 32,
        )

        assert response.ciphertext == b"encrypted_data_here"
        assert len(response.nonce) == 24
        assert len(response.ephemeral_public_key) == 32

    def test_response_respondent_ip_hash_optional(self):
        """respondent_ip_hash should be optional."""
        from app.models.response import Response

        response = Response(
            form_id=uuid4(),
            ciphertext=b"data",
            nonce=b"\x00" * 24,
            ephemeral_public_key=b"\x00" * 32,
        )

        assert response.respondent_ip_hash is None

    def test_response_created_at(self):
        """Response should have created_at timestamp."""
        from app.models.response import Response

        response = Response(
            form_id=uuid4(),
            ciphertext=b"data",
            nonce=b"\x00" * 24,
            ephemeral_public_key=b"\x00" * 32,
        )

        assert response.created_at is not None


class TestTeamKeyModel:
    """Tests for the TeamKey database model."""

    def test_team_key_creation(self):
        """TeamKey should store encrypted form keys for team sharing."""
        from app.models.team_key import TeamKey

        team_key = TeamKey(
            form_id=uuid4(),
            user_id=uuid4(),
            encrypted_form_key=b"encrypted_private_key",
        )

        assert team_key.encrypted_form_key == b"encrypted_private_key"
        assert team_key.created_at is not None
