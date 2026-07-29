# CipherForm — Zero-Knowledge Encrypted Forms

Collect sensitive data without trusting anyone — not even us.

## How It Works

1. **Create a form** — Your browser generates an encryption keypair. The public key goes to our server; the private key stays on your device.
2. **Share the form** — Respondents fill it out. Their browser encrypts responses before sending.
3. **View responses** — Only you can decrypt, using your private key. Our server literally cannot read submissions.

## Tech Stack

- **Backend:** Python 3.12, FastAPI, SQLAlchemy, PostgreSQL
- **Frontend:** React 18, TypeScript, Tailwind CSS
- **Crypto:** NaCl/libsodium (PyNaCl + libsodium-wrappers)
- **Infra:** Docker, GitHub Actions CI/CD

## Development

```bash
# Start services
docker compose up -d

# Backend
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload

# Frontend
cd frontend
npm install
npm run dev

# Run tests
cd backend && pytest tests/ -v
cd frontend && npm test
```

## Security

CipherForm uses zero-knowledge architecture: encryption and decryption happen exclusively in the browser. The server stores only ciphertext and never possesses decryption keys.

- NaCl box (Curve25519 + XSalsa20-Poly1305) for all encryption
- Private keys generated client-side, never transmitted
- Responses encrypted before leaving the respondent's browser
- Team key sharing via public-key re-encryption

## License

All rights reserved. Proprietary software.
