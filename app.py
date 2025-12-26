from flask import Flask, render_template, request, send_file, redirect, url_for, flash
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os
import io
import mimetypes
import logging
import base64
import hashlib
import json
from datetime import datetime
import boto3
from botocore.stub import Stubber
from botocore.exceptions import ClientError
from dotenv import load_dotenv
from functools import wraps
from flask import jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import secrets
import hashlib
import uuid


# Basic logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load .env for local development (ignored by git)
load_dotenv()
if os.environ.get('MASTER_KEY'):
    logger.info('MASTER_KEY loaded from environment')
else:
    logger.info('MASTER_KEY not set; using fallback (not for production)')

app = Flask(__name__)

# --- API key configuration ---
# API keys may be provided via env var API_KEYS (comma-separated) or a single API_KEY
# Keys can also be persisted to a JSON file (default: data/api_keys.json)

PERSIST_KEYS_FILE = os.environ.get('API_KEYS_FILE', 'data/api_keys.json')
ADMIN_KEYS_RAW = os.environ.get('API_ADMIN_KEYS')

# Lightweight OpenAPI spec (served at /openapi.json) and ReDoc UI at /docs
OPENAPI_SPEC = {
    "openapi": "3.0.0",
    "info": {
        "title": "Secure File Share API",
        "version": "1.0.0",
        "description": "API for uploading and managing secure files"
    },
    "paths": {
        "/api/files": {
            "post": {
                "summary": "Upload file",
                "requestBody": {
                    "content": {
                        "multipart/form-data": {
                            "schema": {
                                "type": "object",
                                "properties": {"file": {"type": "string", "format": "binary"}}
                            }
                        }
                    }
                },
                "responses": {"200": {"description": "File uploaded"}}
            }
        },
        "/api/keys": {
            "post": {"summary": "Create API key (admin)"},
            "get": {"summary": "List API keys (admin)"}
        },
        "/api/keys/{key_id}": {"delete": {"summary": "Revoke API key (admin)", "parameters": [{"name": "key_id", "in": "path", "required": True}]}}
    }
}

@app.route('/openapi.json')
def openapi_json():
    return jsonify(OPENAPI_SPEC)


@app.route('/docs')
def api_docs():
    # Serve a minimal ReDoc-based API docs page
    return """<!doctype html>
<html>
  <head>
    <title>API Docs - Secure File Share</title>
    <meta charset="utf-8" />
  </head>
  <body>
    <redoc spec-url='/openapi.json'></redoc>
    <script src="https://cdn.redoc.ly/redoc/latest/bundles/redoc.standalone.js"> </script>
  </body>
</html>"""


def ensure_data_dir():
    d = os.path.dirname(PERSIST_KEYS_FILE)
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)


def _load_api_keys_from_env():
    keys_raw = os.environ.get('API_KEYS') or os.environ.get('API_KEY')
    if not keys_raw:
        return set()
    return {k.strip() for k in keys_raw.split(',') if k.strip()}


def _hash_key(key: str) -> str:
    return hashlib.sha256(key.encode('utf-8')).hexdigest()


def _load_persisted_keys():
    ensure_data_dir()
    fp = PERSIST_KEYS_FILE
    if not os.path.exists(fp):
        return []
    try:
        with open(fp, 'r') as f:
            return json.load(f)
    except Exception:
        return []


def _save_persisted_keys(data):
    ensure_data_dir()
    with open(PERSIST_KEYS_FILE, 'w') as f:
        json.dump(data, f, indent=2)


def _is_valid_api_key(key: str) -> bool:
    # check env keys
    if key in _load_api_keys_from_env():
        return True
    # check persisted hashed keys
    hashed = _hash_key(key)
    for rec in _load_persisted_keys():
        if not rec.get('revoked') and rec.get('hash') == hashed:
            return True
    return False


def _get_auth_header_key():
    # Look in X-API-Key, query param, or Authorization: Bearer <token>
    from flask import request
    key = request.headers.get('X-API-Key')
    if key:
        return key
    key = request.args.get('api_key')
    if key:
        return key
    auth = request.headers.get('Authorization')
    if auth and auth.startswith('Bearer '):
        return auth.split(' ', 1)[1].strip()
    return None


def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = _get_auth_header_key()
        if not key or not _is_valid_api_key(key):
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated


def require_admin_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = _get_auth_header_key()
        # Admin keys read from environment at request time
        admins_raw = os.environ.get('API_ADMIN_KEYS')
        admins = {k.strip() for k in (admins_raw or '').split(',') if k.strip()}
        if key and key in admins:
            return f(*args, **kwargs)
        return jsonify({'error': 'Admin privileges required'}), 403
    return decorated


# --- Rate limiter (per-key if provided, otherwise per-IP) ---
def _limiter_key():
    from flask import request
    return request.headers.get('X-API-Key') or get_remote_address()

# Configure limiter storage using REDIS_URL when available
redis_url = os.environ.get('REDIS_URL')
if redis_url:
    limiter = Limiter(key_func=_limiter_key, app=app, storage_uri=redis_url)
else:
    limiter = Limiter(key_func=_limiter_key, app=app)

@app.context_processor
def inject_now():
    """Provide convenient helpers for templates (UTC and TTL).
    Templates can use `{{ now().year }}` and `{{ download_ttl_hours }}`.
    """
    return {
        'now': datetime.utcnow,
        'download_ttl_hours': int(os.environ.get('DOWNLOAD_TTL_HOURS', app.config.get('DOWNLOAD_TTL_HOURS', 24)))
    }

# Load sensitive config from environment with safe local defaults
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-change-me')
app.config['UPLOAD_FOLDER'] = os.environ.get('UPLOAD_FOLDER', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = int(os.environ.get('MAX_CONTENT_LENGTH', 16 * 1024 * 1024))
app.config['KEYS_FOLDER'] = os.environ.get('KEYS_FOLDER', 'keys')
# Download TTL (hours) - controls how long a key/download link is valid
app.config['DOWNLOAD_TTL_HOURS'] = int(os.environ.get('DOWNLOAD_TTL_HOURS', 24))
app.config['DOWNLOAD_TTL_SECONDS'] = app.config['DOWNLOAD_TTL_HOURS'] * 3600

# Allowed file extensions
ALLOWED_EXTENSIONS = {
    'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 
    'xls', 'xlsx', 'ppt', 'pptx', 'zip', 'rar'
}

# Ensure directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['KEYS_FOLDER'], exist_ok=True)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_key():
    """Generate a secure AES key"""
    return get_random_bytes(32)  # 256-bit key

def encrypt_file(file_data, key):
    """Encrypt file data using AES-GCM (AEAD).

    Format: b'GCM1' + nonce_len(1 byte) + nonce + ciphertext + tag(16 bytes)
    This is backwards-compatible with legacy AES-CBC files (no prefix).
    """
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(file_data)
    nonce = cipher.nonce
    nlen = len(nonce)
    return b'GCM1' + bytes([nlen]) + nonce + ct + tag


def decrypt_file(encrypted_data, key):
    """Decrypt file data supporting AES-GCM (new) and AES-CBC (legacy)."""
    # Detect GCM format by header
    if encrypted_data.startswith(b'GCM1'):
        nlen = encrypted_data[4]
        nonce = encrypted_data[5:5 + nlen]
        tag = encrypted_data[-16:]
        ct = encrypted_data[5 + nlen:-16]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ct, tag)

    # Legacy: AES-CBC (IV + ciphertext)
    iv = encrypted_data[:16]
    ct = encrypted_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt

# --- Key wrapping helpers (encrypt keys at rest) ---
def _get_master_key():
    """Return 32-byte master key derived from MASTER_KEY env var, or None if not set."""
    mk = os.environ.get('MASTER_KEY')
    if mk:
        return hashlib.sha256(mk.encode('utf-8')).digest()
    return None


# --- AWS KMS helpers ---
def _get_kms_client():
    """Return a boto3 KMS client configured from environment."""
    region = os.environ.get('AWS_REGION')
    return boto3.client('kms', region_name=region) if boto3 else None


def kms_encrypt_key(key_bytes):
    """Encrypt key using AWS KMS Encrypt API and return base64 ciphertext."""
    key_id = os.environ.get('AWS_KMS_KEY_ID')
    if not key_id:
        raise RuntimeError('AWS_KMS_KEY_ID not configured')
    client = _get_kms_client()
    resp = client.encrypt(KeyId=key_id, Plaintext=key_bytes)
    blob = resp['CiphertextBlob']
    return base64.b64encode(blob).decode('utf-8')


def kms_decrypt_key(ciphertext_b64):
    """Decrypt base64 ciphertext using AWS KMS Decrypt API and return plaintext bytes."""
    client = _get_kms_client()
    blob = base64.b64decode(ciphertext_b64)
    resp = client.decrypt(CiphertextBlob=blob)
    return resp['Plaintext']


def protect_key(key_bytes):
    """Encrypt (wrap) the per-file symmetric key using master key with AES-GCM or AWS KMS."""
    # Prefer KMS if configured
    if os.environ.get('AWS_KMS_KEY_ID'):
        try:
            ciphertext_b64 = kms_encrypt_key(key_bytes)
            return {'method': 'kms', 'data': ciphertext_b64}
        except Exception as e:
            logger.exception('KMS encrypt failed, falling back to local master key: %s', e)

    mk = _get_master_key()
    if not mk:
        # Fallback: store plain base64 with method 'plain' (for compatibility)
        return {'method': 'plain', 'data': base64.b64encode(key_bytes).decode('utf-8')}
    cipher = AES.new(mk, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(key_bytes)
    payload = base64.b64encode(cipher.nonce + ct + tag).decode('utf-8')
    return {'method': 'gcm', 'data': payload}

def unprotect_key(stored):
    """Decrypt (unwrap) the stored key."""
    # Legacy support: stored might be a plain base64 string
    if not isinstance(stored, dict) or 'method' not in stored:
        return base64.b64decode(stored)

    method = stored.get('method')
    data = stored.get('data')
    if method == 'plain':
        return base64.b64decode(data)

    if method == 'kms':
        try:
            return kms_decrypt_key(data)
        except Exception as e:
            logger.exception('KMS decrypt failed: %s', e)
            raise

    mk = _get_master_key()
    if not mk:
        raise RuntimeError('MASTER_KEY not set; cannot decrypt stored keys')

    raw = base64.b64decode(data)
    nonce = raw[:16]
    tag = raw[-16:]
    ct = raw[16:-16]
    cipher = AES.new(mk, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)

def save_key_mapping(file_id, key, filename):
    """Save encryption key mapping (wrapped using MASTER_KEY)."""
    wrapped = protect_key(key)
    key_data = {
        'enc_key': wrapped,
        'original_filename': filename,
        'timestamp': datetime.now().isoformat()
    }
    key_path = os.path.join(app.config['KEYS_FOLDER'], f'{file_id}.json')
    with open(key_path, 'w') as f:
        json.dump(key_data, f)
    return file_id

def get_key_mapping(file_id):
    """Retrieve encryption key mapping and unwrap the per-file key. Enforce TTL expiry."""
    key_path = os.path.join(app.config['KEYS_FOLDER'], f'{file_id}.json')
    if not os.path.exists(key_path):
        return None
    with open(key_path, 'r') as f:
        key_data = json.load(f)

    # Enforce TTL if timestamp present
    ts = key_data.get('timestamp')
    if ts:
        try:
            created = datetime.fromisoformat(ts)
            age_seconds = (datetime.now() - created).total_seconds()
            if age_seconds > app.config.get('DOWNLOAD_TTL_SECONDS', 24 * 3600):
                logger.info('Key mapping %s expired (age %.0f seconds)', file_id, age_seconds)
                return None
        except Exception:
            # if timestamp parsing fails, be conservative and reject
            logger.exception('Failed to parse timestamp for %s, rejecting as expired', file_id)
            return None

    enc = key_data.get('enc_key') or key_data.get('key')
    try:
        if isinstance(enc, dict):
            key_bytes = unprotect_key(enc)
        else:
            # legacy base64 string
            key_bytes = base64.b64decode(enc)
    except Exception as e:
        logger.exception('Failed to unwrap key for %s: %s', file_id, e)
        return None

    key_data['key'] = key_bytes
    return key_data

@app.route('/')
def index():
    """Home page"""
    return render_template('index.html')

@app.route('/download', methods=['GET'])
def download_page():
    """Render the download form page"""
    return render_template('download.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    """Handle file upload and encryption"""
    if request.method == 'POST':
        # Check if file was submitted
        if 'file' not in request.files:
            flash('No file selected')
            return redirect(request.url)
        
        file = request.files['file']
        
        # Check if file is selected
        if file.filename == '':
            flash('No file selected')
            return redirect(request.url)
        
        # Check if file type is allowed
        if not allowed_file(file.filename):
            flash('File type not allowed')
            return redirect(request.url)
        
        # Secure the filename
        filename = secure_filename(file.filename)
        
        # Read file data
        file_data = file.read()
        
        # Generate encryption key
        encryption_key = generate_key()
        
        # Encrypt file data
        encrypted_data = encrypt_file(file_data, encryption_key)
        
        # Generate unique file ID
        file_id = hashlib.sha256(
            filename.encode() + encryption_key + get_random_bytes(16)
        ).hexdigest()[:16]
        
        # Save encrypted file
        encrypted_filename = f"{file_id}.enc"
        encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
        
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted_data)
        
        # Save key mapping
        share_id = save_key_mapping(file_id, encryption_key, filename)
        
        # Generate download URL
        download_url = url_for('download_file', file_id=share_id, _external=True)
        
        return render_template('upload.html', 
                             download_url=download_url,
                             file_id=share_id,
                             filename=filename)
    
    return render_template('upload.html')

@app.route('/download/<file_id>')
def download_file(file_id):
    """Handle file download and decryption"""
    try:
        # Get key mapping
        key_data = get_key_mapping(file_id)
        
        if not key_data:
            flash('File not found or link expired')
            return redirect(url_for('index'))
        
        # Load encrypted file
        encrypted_filename = f"{file_id}.enc"
        encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
        
        if not os.path.exists(encrypted_path):
            flash('File not found')
            return redirect(url_for('index'))
        
        with open(encrypted_path, 'rb') as f:
            encrypted_data = f.read()
        
        # Decrypt file
        decrypted_data = decrypt_file(encrypted_data, key_data['key'])

        # Serve decrypted file directly from memory to avoid writing plaintext to disk
        temp_filename = key_data['original_filename']
        fileobj = io.BytesIO(decrypted_data)
        mimetype, _ = mimetypes.guess_type(temp_filename)
        mimetype = mimetype or 'application/octet-stream'
        fileobj.seek(0)
        return send_file(
            fileobj,
            as_attachment=True,
            download_name=temp_filename,
            mimetype=mimetype
        )    
    except Exception as e:
        flash(f'Error downloading file: {str(e)}')
        return redirect(url_for('index'))

@app.route('/api/files', methods=['POST'])
@require_api_key
@limiter.limit('10 per minute')
def api_upload():
    """API endpoint for file upload (requires API key and rate limited)
    ---
    tags:
      - files
    consumes:
      - multipart/form-data
    parameters:
      - name: file
        in: formData
        type: file
        required: true
        description: The file to upload
    responses:
      200:
        description: File uploaded
        schema:
          type: object
          properties:
            file_id:
              type: string
            download_url:
              type: string
            filename:
              type: string
    """
    if 'file' not in request.files:
        return {'error': 'No file provided'}, 400
    
    file = request.files['file']
    
    if file.filename == '':
        return {'error': 'No file selected'}, 400
    
    if not allowed_file(file.filename):
        return {'error': 'File type not allowed'}, 400
    
    filename = secure_filename(file.filename)
    file_data = file.read()
    encryption_key = generate_key()
    encrypted_data = encrypt_file(file_data, encryption_key)
    
    file_id = hashlib.sha256(
        filename.encode() + encryption_key + get_random_bytes(16)
    ).hexdigest()[:16]
    
    encrypted_filename = f"{file_id}.enc"
    encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
    
    with open(encrypted_path, 'wb') as f:
        f.write(encrypted_data)
    
    share_id = save_key_mapping(file_id, encryption_key, filename)
    download_url = url_for('download_file', file_id=share_id, _external=True)
    
    return {
        'file_id': share_id,
        'download_url': download_url,
        'filename': filename,
        'message': 'File uploaded and encrypted successfully'
    }


# --- API Key management endpoints ---
@app.route('/api/keys', methods=['POST'])
@require_admin_key
def create_api_key():
    """Create a new API key (admin-only)
    ---
    tags:
      - keys
    responses:
      200:
        description: Created key
        schema:
          type: object
          properties:
            id:
              type: string
            key:
              type: string
    """
    # generate key
    new_key = secrets.token_urlsafe(32)
    hashed = _hash_key(new_key)
    rec = {
        'id': uuid.uuid4().hex,
        'hash': hashed,
        'created_at': datetime.now().isoformat(),
        'revoked': False
    }
    data = _load_persisted_keys()
    data.append(rec)
    _save_persisted_keys(data)
    # return plain key only once
    return {'id': rec['id'], 'key': new_key}


@app.route('/api/keys', methods=['GET'])
@require_admin_key
def list_api_keys():
    """List API keys (admin-only)
    ---
    tags:
      - keys
    responses:
      200:
        description: List of keys (hashed)
    """
    data = _load_persisted_keys()
    return {'keys': [{'id': r['id'], 'created_at': r.get('created_at'), 'revoked': r.get('revoked', False)} for r in data]}


@app.route('/api/keys/<key_id>', methods=['DELETE'])
@require_admin_key
def revoke_api_key(key_id):
    """Revoke an API key (admin-only)
    ---
    tags:
      - keys
    parameters:
      - in: path
        name: key_id
        type: string
        required: true
    responses:
      200:
        description: Revoked
    """
    data = _load_persisted_keys()
    found = False
    for r in data:
        if r['id'] == key_id:
            r['revoked'] = True
            found = True
    _save_persisted_keys(data)
    if not found:
        return {'error': 'Not found'}, 404
    return {'status': 'revoked'}

if __name__ == '__main__':
    app.run(debug=True, ssl_context='adhoc')  # Use adhoc SSL for testing