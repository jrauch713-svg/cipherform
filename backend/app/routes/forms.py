"""Form CRUD and encrypted response submission routes."""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.form import Form
from app.models.response import Response
from app.routes.auth import get_current_user
from app.models.user import User

router = APIRouter(prefix="/api", tags=["forms"])


# ── Schemas ───────────────────────────────────────────────────────────────────


class FormCreate(BaseModel):
    """Request body for creating a form."""

    title: str
    description: str | None = None
    public_key: str
    fields: list[dict] = Field(default_factory=list)


class FormUpdate(BaseModel):
    """Request body for updating a form."""

    title: str | None = None
    description: str | None = None
    is_active: bool | None = None


class FormResponse(BaseModel):
    """Public form data (metadata only, no private key)."""

    id: str
    title: str
    description: str | None
    public_key: str
    fields: list
    response_count: int
    is_active: bool
    created_at: str
    updated_at: str

    model_config = {"from_attributes": True}


class ResponseSubmission(BaseModel):
    """Encrypted response submission from a form respondent."""

    ciphertext: str  # base64-encoded ciphertext
    nonce: str  # base64-encoded nonce
    ephemeral_public_key: str  # base64-encoded ephemeral public key


class ResponseOut(BaseModel):
    """Encrypted response data returned to the form owner."""

    id: str
    ciphertext: str
    nonce: str
    ephemeral_public_key: str
    created_at: str

    model_config = {"from_attributes": True}


# ── Form CRUD ─────────────────────────────────────────────────────────────────


@router.post("/forms", response_model=FormResponse, status_code=status.HTTP_201_CREATED)
async def create_form(
    request: FormCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a new encrypted form."""
    form = Form(
        user_id=user.id,
        title=request.title,
        description=request.description,
        public_key=request.public_key,
        fields=request.fields,
    )
    db.add(form)
    await db.flush()
    await db.refresh(form)
    return _form_to_response(form)


@router.get("/forms", response_model=list[FormResponse])
async def list_forms(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all forms owned by the current user."""
    result = await db.execute(
        select(Form)
        .where(Form.user_id == user.id)
        .order_by(Form.created_at.desc())
    )
    forms = result.scalars().all()
    return [_form_to_response(f) for f in forms]


@router.get("/forms/{form_id}", response_model=FormResponse)
async def get_form(
    form_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get a specific form owned by the user."""
    form = await _get_owned_form(form_id, user.id, db)
    return _form_to_response(form)


@router.patch("/forms/{form_id}", response_model=FormResponse)
async def update_form(
    form_id: str,
    request: FormUpdate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update a form's metadata."""
    form = await _get_owned_form(form_id, user.id, db)

    if request.title is not None:
        form.title = request.title
    if request.description is not None:
        form.description = request.description
    if request.is_active is not None:
        form.is_active = request.is_active

    await db.flush()
    await db.refresh(form)
    return _form_to_response(form)


@router.delete("/forms/{form_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_form(
    form_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete a form and all its responses."""
    form = await _get_owned_form(form_id, user.id, db)
    await db.delete(form)
    await db.flush()


# ── Encrypted Responses ───────────────────────────────────────────────────────


@router.post("/forms/{form_id}/responses", response_model=ResponseOut, status_code=status.HTTP_201_CREATED)
async def submit_response(
    form_id: str,
    request: ResponseSubmission,
    db: AsyncSession = Depends(get_db),
):
    """Submit an encrypted response to a form. No authentication required."""
    # Verify form exists and is active
    result = await db.execute(
        select(Form).where(Form.id == form_id, Form.is_active == True)
    )
    form = result.scalar_one_or_none()
    if form is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Form not found")

    import base64

    response = Response(
        form_id=form_id,
        ciphertext=base64.b64decode(request.ciphertext),
        nonce=base64.b64decode(request.nonce),
        ephemeral_public_key=base64.b64decode(request.ephemeral_public_key),
    )
    db.add(response)

    # Increment response count
    form.response_count = (form.response_count or 0) + 1

    await db.flush()
    await db.refresh(response)

    return ResponseOut(
        id=response.id,
        ciphertext=request.ciphertext,
        nonce=request.nonce,
        ephemeral_public_key=request.ephemeral_public_key,
        created_at=response.created_at.isoformat() if response.created_at else "",
    )


@router.get("/forms/{form_id}/responses", response_model=list[ResponseOut])
async def list_responses(
    form_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all encrypted responses for a form. Form owner only."""
    await _get_owned_form(form_id, user.id, db)

    import base64

    result = await db.execute(
        select(Response)
        .where(Response.form_id == form_id)
        .order_by(Response.created_at.desc())
    )
    responses = result.scalars().all()

    return [
        ResponseOut(
            id=r.id,
            ciphertext=base64.b64encode(r.ciphertext).decode("ascii"),
            nonce=base64.b64encode(r.nonce).decode("ascii"),
            ephemeral_public_key=base64.b64encode(r.ephemeral_public_key).decode("ascii"),
            created_at=r.created_at.isoformat() if r.created_at else "",
        )
        for r in responses
    ]


@router.get("/forms/{form_id}/responses/{response_id}", response_model=ResponseOut)
async def get_response(
    form_id: str,
    response_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get a specific encrypted response. Form owner only."""
    await _get_owned_form(form_id, user.id, db)

    import base64

    result = await db.execute(
        select(Response).where(Response.id == response_id, Response.form_id == form_id)
    )
    response = result.scalar_one_or_none()
    if response is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Response not found")

    return ResponseOut(
        id=response.id,
        ciphertext=base64.b64encode(response.ciphertext).decode("ascii"),
        nonce=base64.b64encode(response.nonce).decode("ascii"),
        ephemeral_public_key=base64.b64encode(response.ephemeral_public_key).decode("ascii"),
        created_at=response.created_at.isoformat() if response.created_at else "",
    )


# ── Helpers ───────────────────────────────────────────────────────────────────


async def _get_owned_form(form_id: str, user_id: str, db: AsyncSession) -> Form:
    """Get a form by ID, verifying it belongs to the given user."""
    result = await db.execute(
        select(Form).where(Form.id == form_id, Form.user_id == user_id)
    )
    form = result.scalar_one_or_none()
    if form is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Form not found")
    return form


def _form_to_response(form: Form) -> dict:
    """Convert a Form model to a response dict."""
    return {
        "id": form.id,
        "title": form.title,
        "description": form.description,
        "public_key": form.public_key,
        "fields": form.fields or [],
        "response_count": form.response_count or 0,
        "is_active": form.is_active if form.is_active is not None else True,
        "created_at": form.created_at.isoformat() if form.created_at else "",
        "updated_at": form.updated_at.isoformat() if form.updated_at else "",
    }
