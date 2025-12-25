# 🔐 Secure File Sharing System

A web-based secure file sharing system with military-grade AES-256 encryption.

## Features
- End-to-end file encryption with AES-256-GCM (authenticated, AEAD)
- Key wrapping at rest using a master key (optional, via `MASTER_KEY` env var)
- User-friendly web interface
- REST API for programmatic access
- Drag-and-drop file upload
- Automatic file type validation

## Installation

### Prerequisites
- Python 3.8+
- pip (Python package manager)
- (Optional) For production: a cloud KMS (AWS KMS / Azure Key Vault) or other secure key management system

## Security notes
- Keys are wrapped at rest using AES-GCM protected by the `MASTER_KEY` environment variable when provided. The app also supports **AWS KMS** to wrap keys — set `AWS_KMS_KEY_ID` and the app will use KMS Encrypt/Decrypt.
- In production, prefer a KMS (AWS KMS or Azure Key Vault) instead of static passphrases; use IAM roles/managed identities and audit logs.
- The app avoids writing decrypted files to disk by serving decrypted data from memory. This reduces the risk of plaintext leakage but does not replace secure infrastructure.
- Rotate keys regularly and enforce short TTLs for download links (configurable via `DOWNLOAD_TTL_HOURS`, default: 24).

---

### AWS KMS (quick setup)
1. Create a KMS key (Customer Master Key) in AWS KMS and note the Key ID or ARN.
2. Grant your application IAM permission to call `kms:Encrypt` and `kms:Decrypt` on that key (use a role for EC2/ECS/Lambda or short-lived credentials).
3. Set environment variables in your deployment: `AWS_KMS_KEY_ID` (KeyId or ARN) and optionally `AWS_REGION`.
4. The app will automatically use KMS to protect per-file keys when `AWS_KMS_KEY_ID` is present.

I implemented a migration script to re-wrap existing key mappings into KMS. See `scripts/migrate_keys_to_kms.py` for usage; run with `--dry-run` first and then re-run with `--yes` to apply changes. Example:

```bash
# dry run
python scripts/migrate_keys_to_kms.py --keys-folder keys --dry-run

# apply (ensure AWS_KMS_KEY_ID and AWS credentials are configured)
python scripts/migrate_keys_to_kms.py --keys-folder keys --backup-dir keys_backup --yes
```


### Setup
1. Clone the repository:
```bash
git clone https://github.com/yourusername/secure-file-share.git
cd secure-file-share
```

2. Create a virtual environment and install dependencies:
```bash
python -m venv .venv
.\.venv\Scripts\activate  # Windows
pip install -r requirements.txt
```

### Environment variables
This project uses a master key to protect per-file encryption keys at rest. For local development set the `MASTER_KEY` environment variable (a passphrase). Example (PowerShell):
```powershell
$env:MASTER_KEY = "your-local-master-key"
```
If `MASTER_KEY` is not set, the app falls back to storing per-file keys encoded in base64 (for compatibility only). In production you should use a secure KMS instead (see Security notes below).

### Running tests
Run the unit tests with pytest:
```bash
pytest -q
```
