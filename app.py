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
    """Encrypt file data using AES-256-CBC"""
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(file_data, AES.block_size))
    iv = cipher.iv
    return iv + ct_bytes

def decrypt_file(encrypted_data, key):
    """Decrypt file data using AES-256-CBC"""
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
def api_upload():
    """API endpoint for file upload"""
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

if __name__ == '__main__':
    app.run(debug=True, ssl_context='adhoc')  # Use adhoc SSL for testing