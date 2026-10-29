# IP Evidence Hub

A Flask web application for intellectual-property evidence management: fingerprint files with SHA-256, keep them off-chain, and anchor their hashes on the MST blockchain (Coral Testnet or Mainnet).

## Features

**Accounts and security**
- Registration, login, logout (POST with CSRF token) and change password
- Password hashing, CSRF protection on every form, HttpOnly/SameSite session cookies with an 8-hour lifetime
- Login lockout after 5 failed attempts per IP + account for 15 minutes
- Security headers (CSP, X-Frame-Options, nosniff, Referrer-Policy)
- User/admin roles

**Evidence**
- Uploads with extension and size checks, SHA-256 fingerprints and integrity status
- Off-chain local file storage with SQLite metadata
- Duplicate detection: warns when an identical file was already recorded
- Version history: register new versions of a work linked to the original
- Image watermarking with Pillow (original is preserved)
- PDF evidence certificate with QR code, including blockchain transaction details
- Dashboard search (title, description, filename, hash prefix) and blockchain-status filter

**Blockchain (MST)**
- Anchor a hash with **MetaMask** (user's wallet signs in the browser) or with a **server wallet** (key in `.env`)
- The server verifies every transaction on-chain: successful receipt, sent to the configured registry contract, and an `EvidenceRegistered` event for this exact hash
- Pending transactions can be refreshed; explorer links on the detail page, public page and certificate

**Public tools**
- Verify a file against a known hash
- Hash lookup: by hash or file, shows the earliest record in the hub and the on-chain registration
- Public verification page per record (linked from the certificate QR code)

**Administration**
- Promote or demote users (admins cannot change their own role)
- System-wide audit log with action filter

## Quick start

Python 3.10+ recommended.

### 1. Create environment

Windows PowerShell:
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

Linux/macOS:
```bash
python -m venv .venv
source .venv/bin/activate
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```
For running tests: `pip install -r requirements-dev.txt`

### 3. Configure environment
Copy `.env.example` to `.env` and set at least `FLASK_SECRET_KEY` and `ADMIN_PASSWORD`. If `FLASK_SECRET_KEY` is not set, a random key is generated at startup and all sessions end when the app restarts.

| Variable | Default | Purpose |
|---|---|---|
| `FLASK_SECRET_KEY` | random per start | Session signing key |
| `ADMIN_USERNAME` / `ADMIN_EMAIL` / `ADMIN_PASSWORD` | `admin` / `admin@example.com` / `ChangeMe123!` | Seeded once, when no admin exists |
| `DATABASE_PATH` | `ip_evidence.db` | SQLite file (relative to the app folder or absolute) |
| `STORAGE_PATH` | `storage` | Off-chain file storage folder |
| `MAX_UPLOAD_MB` | `25` | Upload size limit |
| `SESSION_COOKIE_SECURE` | `false` | Set `true` when served over HTTPS |
| `MST_NETWORK` | `coral-testnet` | `coral-testnet` or `mainnet` |
| `CONTRACT_ADDRESS` | empty | Deployed `IPEvidenceRegistry` address; anchoring is disabled until set |
| `MST_SIGNER_PRIVATE_KEY` | empty | Optional server wallet key; enables "Anchor with server wallet" |
| `MST_RPC_URL` / `MST_EXPLORER_URL` / `MST_CURRENCY_SYMBOL` | network defaults | Optional overrides |

### 4. Run
```bash
python app.py
```
Open http://127.0.0.1:5000 and log in with the admin account. `/health` reports the selected network and whether a contract is configured.

### 5. Test
```bash
python -m pytest
```
Tests use an in-memory stand-in for the MST chain; they do not contact any network.

## MST network settings

| | Coral Testnet | Mainnet |
|---|---|---|
| `MST_NETWORK` | `coral-testnet` | `mainnet` |
| Chain ID | `54635` | `4646` |
| RPC | `https://coralrpc.mstblockchain.com` | `https://4646.rpc.thirdweb.com` |
| Explorer | `https://coral.mstscan.com` | `https://mstscan.com` |

Verify these endpoints and the native currency symbol against MST's official developer documentation before deploying. On the first chain call the app checks that the RPC's chain ID matches the selected network and refuses to continue if it does not. The older MST testnet (chain ID 91562037) has a published deprecation notice; use Coral Testnet for new testing.

## Smart contract deployment

1. Open `contracts/IPEvidenceRegistry.sol` in https://remix.ethereum.org and compile with Solidity 0.8.20+.
2. In MetaMask, add MST Coral Testnet (settings above) and obtain test tokens from MST's official faucet or community.
3. In Remix, choose **Injected Provider - MetaMask** and deploy.
4. Put the deployed address in `.env` as `CONTRACT_ADDRESS` and restart the app.
5. Optional server wallet: create a dedicated wallet, fund it with a small amount of MST, and set `MST_SIGNER_PRIVATE_KEY`. Never use a personal wallet key, never commit `.env`, and keep only small balances on the server wallet.

Deploy separately on Mainnet when you switch `MST_NETWORK=mainnet`; each network needs its own contract address.

### How anchoring works

- The contract stores `sha256 digest → (registrant, block timestamp, reference ID)`. The reference ID is `IPEH-<evidence id>`; no file content or personal data goes on-chain.
- Each hash can be registered once. If a hash is already on-chain, the app shows the existing registrant and time instead of sending a transaction.
- **MetaMask**: the evidence page builds the call data on the server, MetaMask switches to (or adds) the MST network and sends the transaction, and the server then verifies the transaction before recording it.
- **Server wallet**: the server signs and sends the transaction and waits up to 120 seconds for the receipt. If it is not mined in time, the status stays *Pending confirmation* until you click **Refresh status**.

## Limitations and production checklist

This is a runnable project, not a security-audited production system.

- A hash proves file-byte integrity. A block timestamp proves the hash existed no later than that block. Neither alone proves authorship or legal ownership.
- SQLite and local storage suit demos and single-host deployments. Production should use managed database/object storage, encrypted backups, malware scanning, email verification, password reset and MFA.
- The public verification page reveals the title, filename, hash, size and timestamps. Avoid putting personal or confidential metadata in titles or filenames.
- Image watermarking is a visible label, not an unremovable watermark.
- Run behind HTTPS with `SESSION_COOKIE_SECURE=true` and debug disabled. Login lockout is per IP + account and stored in SQLite.
- A server wallet key in `.env` is suitable for demos; production should use a secret manager or a hardware/KMS signer.

## Project layout

```text
ip_evidence_hub/
  app.py                  Flask routes, database, uploads, reports
  chain.py                MST network config and registry contract client (web3.py)
  contracts/IPEvidenceRegistry.sol
  static/style.css
  static/wallet.js        MetaMask anchoring
  templates/
  tests/                  pytest suite (FakeChain stand-in in tests/fakes.py)
  requirements.txt
  requirements-dev.txt
  storage/
```
