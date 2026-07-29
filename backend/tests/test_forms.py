"""Tests for form CRUD and encrypted response endpoints."""

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


@pytest.fixture
async def client():
    """Async test client for the FastAPI app."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.fixture
async def auth_headers(client):
    """Register a user and return auth headers."""
    response = await client.post(
        "/api/auth/register",
        json={
            "email": "formowner@example.com",
            "password": "securepassword",
            "public_key": "base64formownerpk",
        },
    )
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


class TestFormCRUD:
    """Tests for form create, read, update, delete."""

    @pytest.mark.asyncio
    async def test_create_form(self, client, auth_headers):
        """Should create a new form successfully."""
        response = await client.post(
            "/api/forms",
            json={
                "title": "Client Intake Form",
                "description": "New client information collection",
                "public_key": "base64formpublickey123",
                "fields": [
                    {"name": "full_name", "type": "text", "required": True},
                    {"name": "email", "type": "email", "required": True},
                ],
            },
            headers=auth_headers,
        )

        assert response.status_code == 201
        data = response.json()
        assert data["title"] == "Client Intake Form"
        assert data["public_key"] == "base64formpublickey123"
        assert len(data["fields"]) == 2
        assert "id" in data
        assert "created_at" in data

    @pytest.mark.asyncio
    async def test_create_form_unauthenticated(self, client):
        """Should reject unauthenticated form creation."""
        response = await client.post(
            "/api/forms",
            json={"title": "Test", "public_key": "pk"},
        )
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_create_form_missing_title(self, client, auth_headers):
        """Should reject form creation without title."""
        response = await client.post(
            "/api/forms",
            json={"public_key": "pk"},
            headers=auth_headers,
        )
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_list_forms(self, client, auth_headers):
        """Should list user's forms."""
        # Create 2 forms
        await client.post(
            "/api/forms",
            json={"title": "Form 1", "public_key": "pk1"},
            headers=auth_headers,
        )
        await client.post(
            "/api/forms",
            json={"title": "Form 2", "public_key": "pk2"},
            headers=auth_headers,
        )

        response = await client.get("/api/forms", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2
        titles = {f["title"] for f in data}
        assert titles == {"Form 1", "Form 2"}

    @pytest.mark.asyncio
    async def test_get_form(self, client, auth_headers):
        """Should get a specific form by ID."""
        create_response = await client.post(
            "/api/forms",
            json={"title": "My Form", "public_key": "mypk"},
            headers=auth_headers,
        )
        form_id = create_response.json()["id"]

        response = await client.get(f"/api/forms/{form_id}", headers=auth_headers)
        assert response.status_code == 200
        assert response.json()["title"] == "My Form"

    @pytest.mark.asyncio
    async def test_get_form_not_found(self, client, auth_headers):
        """Should return 404 for non-existent form."""
        response = await client.get(
            "/api/forms/nonexistent-id", headers=auth_headers
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_update_form(self, client, auth_headers):
        """Should update a form's title and description."""
        create_response = await client.post(
            "/api/forms",
            json={"title": "Old Title", "public_key": "pk"},
            headers=auth_headers,
        )
        form_id = create_response.json()["id"]

        response = await client.patch(
            f"/api/forms/{form_id}",
            json={"title": "New Title", "description": "Updated description"},
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert data["title"] == "New Title"
        assert data["description"] == "Updated description"

    @pytest.mark.asyncio
    async def test_delete_form(self, client, auth_headers):
        """Should delete a form."""
        create_response = await client.post(
            "/api/forms",
            json={"title": "To Delete", "public_key": "pk"},
            headers=auth_headers,
        )
        form_id = create_response.json()["id"]

        response = await client.delete(f"/api/forms/{form_id}", headers=auth_headers)
        assert response.status_code == 204

        # Verify deletion
        get_response = await client.get(f"/api/forms/{form_id}", headers=auth_headers)
        assert get_response.status_code == 404


class TestEncryptedResponseSubmission:
    """Tests for the encrypted response submission and retrieval flow."""

    @pytest.mark.asyncio
    async def test_submit_encrypted_response(self, client, auth_headers):
        """Should accept an encrypted response blob."""
        # Create a form first
        create_response = await client.post(
            "/api/forms",
            json={"title": "Survey", "public_key": "base64pk"},
            headers=auth_headers,
        )
        form_id = create_response.json()["id"]

        # Submit encrypted response (as a respondent, no auth needed)
        response = await client.post(
            f"/api/forms/{form_id}/responses",
            json={
                "ciphertext": "dGVzdCBjaXBoZXJ0ZXh0",  # base64 of "test ciphertext"
                "nonce": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX",
                "ephemeral_public_key": "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=",
            },
        )

        assert response.status_code == 201
        data = response.json()
        assert "id" in data
        assert "created_at" in data

    @pytest.mark.asyncio
    async def test_submit_response_no_auth_required(self, client, auth_headers):
        """Response submission should NOT require authentication (public form)."""
        create_response = await client.post(
            "/api/forms",
            json={"title": "Public Survey", "public_key": "pk"},
            headers=auth_headers,
        )
        form_id = create_response.json()["id"]

        # Submit without auth headers
        response = await client.post(
            f"/api/forms/{form_id}/responses",
            json={
                "ciphertext": "dGVzdA==",
                "nonce": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX",
                "ephemeral_public_key": "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=",
            },
        )
        assert response.status_code == 201

    @pytest.mark.asyncio
    async def test_submit_response_to_nonexistent_form(self, client):
        """Should return 404 for non-existent form."""
        response = await client.post(
            "/api/forms/nonexistent/responses",
            json={
                "ciphertext": "dGVzdA==",
                "nonce": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX",
                "ephemeral_public_key": "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=",
            },
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_get_responses(self, client, auth_headers):
        """Form owner should be able to list response metadata (NOT plaintext)."""
        create_response = await client.post(
            "/api/forms",
            json={"title": "Form With Responses", "public_key": "pk"},
            headers=auth_headers,
        )
        form_id = create_response.json()["id"]

        # Submit 2 responses
        for _ in range(2):
            await client.post(
                f"/api/forms/{form_id}/responses",
                json={
                    "ciphertext": "dGVzdA==",
                    "nonce": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX",
                    "ephemeral_public_key": "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=",
                },
            )

        # Retrieve responses as form owner
        response = await client.get(
            f"/api/forms/{form_id}/responses", headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2
        # Response metadata should be present but plaintext should NOT be
        assert "id" in data[0]
        assert "created_at" in data[0]
        assert "ciphertext" in data[0]  # encrypted blob is returned for client decryption

    @pytest.mark.asyncio
    async def test_get_response_encrypted_blob(self, client, auth_headers):
        """Should return the full encrypted payload for a specific response."""
        create_response = await client.post(
            "/api/forms",
            json={"title": "Single Response", "public_key": "pk"},
            headers=auth_headers,
        )
        form_id = create_response.json()["id"]

        submit_response = await client.post(
            f"/api/forms/{form_id}/responses",
            json={
                "ciphertext": "c3BlY2lmaWMgY2lwaGVydGV4dA==",
                "nonce": "QUJDREVGR0hJS0xNTk9QUVJTVFVWV1hZWg==",
                "ephemeral_public_key": "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
            },
        )
        response_id = submit_response.json()["id"]

        response = await client.get(
            f"/api/forms/{form_id}/responses/{response_id}", headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["ciphertext"] == "c3BlY2lmaWMgY2lwaGVydGV4dA=="
        assert "nonce" in data
        assert "ephemeral_public_key" in data

    @pytest.mark.asyncio
    async def test_get_responses_unauthenticated(self, client, auth_headers):
        """Should reject unauthenticated access to responses."""
        create_response = await client.post(
            "/api/forms",
            json={"title": "Private Form", "public_key": "pk"},
            headers=auth_headers,
        )
        form_id = create_response.json()["id"]

        response = await client.get(f"/api/forms/{form_id}/responses")
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_form_response_count_increments(self, client, auth_headers):
        """Form response_count should increment with each submission."""
        create_response = await client.post(
            "/api/forms",
            json={"title": "Counting Form", "public_key": "pk"},
            headers=auth_headers,
        )
        form_id = create_response.json()["id"]

        # Submit 3 responses
        for _ in range(3):
            await client.post(
                f"/api/forms/{form_id}/responses",
                json={
                    "ciphertext": "dA==",
                    "nonce": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX",
                    "ephemeral_public_key": "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=",
                },
            )

        # Check form metadata
        form_response = await client.get(f"/api/forms/{form_id}", headers=auth_headers)
        assert form_response.json()["response_count"] == 3
