# CipherForm — Development Standards

## Iron Rules

1. **TDD mandatory.** RED → GREEN → REFACTOR for every code change. No exceptions.
2. **Feature branches only.** `feat/*`, `fix/*`, `chore/*`. Never commit to main.
3. **PR required for merge.** Every change goes through PR review.
4. **Conventional commits.** `feat:`, `fix:`, `test:`, `chore:`, `docs:`, `refactor:`
5. **Security scan before push.** No secrets, tokens, or keys in code.

## Branch Naming

```
feat/encrypted-form-submission
fix/rate-limit-bypass
chore/update-dependencies
```

## Commit Convention

```
feat: add NaCl encryption service
fix: handle empty form submissions gracefully
test: add encrypted response decryption test
chore: bump fastapi to 0.115.0
docs: document encryption protocol
refactor: extract key management to separate module
```

## Code Quality Gates

All must pass before merge:

```bash
# Backend
ruff check .
mypy backend/app/
pytest tests/ -v --cov=app --cov-report=term-missing

# Frontend
npm run lint
npm test
```

- Zero ruff violations
- Zero mypy errors
- 100% test pass rate
- >80% code coverage
- No console.log, no debug prints, no commented-out code

## Testing Standards

- **Unit tests:** Every service function tested in isolation
- **Integration tests:** Every API endpoint tested with real DB
- **E2E tests:** Critical path (create form → submit → decrypt) tested end-to-end
- **Crypto tests:** Every encryption function tested for correctness, roundtrip, and failure modes

## Security Requirements

1. Private keys NEVER logged, stored on server, or transmitted
2. All crypto operations client-side only
3. Server stores ONLY ciphertext + metadata
4. No plaintext in DB dumps, logs, or error messages
5. HTTPS enforced (HSTS in production)
6. Rate limiting on all public endpoints
7. Parameterized queries (SQLAlchemy) — no raw SQL
8. CSRF protection on state-changing endpoints
9. CSP headers in production
10. Regular `pip-audit` and `npm audit`

## Local Development

```bash
# Set up
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt

# Run services
docker compose up -d  # postgres, redis

# Backend
cd backend && uvicorn app.main:app --reload --port 8000

# Frontend
cd frontend && npm install && npm run dev

# Run tests
cd backend && pytest tests/ -v
cd frontend && npm test
```
