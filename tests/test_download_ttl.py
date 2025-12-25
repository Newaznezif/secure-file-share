import json
import base64
from datetime import datetime, timedelta
from pathlib import Path
import sys
import os

import pytest

# Ensure project root is on sys.path for importing app
ROOT = os.path.dirname(os.path.dirname(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from app import app, get_key_mapping


def write_key_file(folder: Path, file_id: str, key_bytes: bytes, hours_offset: int = 0):
    ts = (datetime.now() + timedelta(hours=hours_offset)).isoformat()
    data = {
        'enc_key': {'method': 'plain', 'data': base64.b64encode(key_bytes).decode('utf-8')},
        'original_filename': 'secret.txt',
        'timestamp': ts
    }
    p = folder / f"{file_id}.json"
    p.write_text(json.dumps(data))
    return p


def test_get_key_mapping_respects_ttl(tmp_path, monkeypatch):
    # Arrange
    monkeypatch.setenv('KEYS_FOLDER', str(tmp_path))
    # update app config (import-time env var may be set already)
    app.config['KEYS_FOLDER'] = str(tmp_path)
    app.config['DOWNLOAD_TTL_HOURS'] = 24
    app.config['DOWNLOAD_TTL_SECONDS'] = 24 * 3600

    file_id = 'deadbeefdeadbeef'
    # write a file with timestamp 25 hours ago
    write_key_file(tmp_path, file_id, b'secret-key-bytes', hours_offset=-25)

    # Act
    result = get_key_mapping(file_id)

    # Assert
    assert result is None


def test_get_key_mapping_allows_recent(tmp_path, monkeypatch):
    monkeypatch.setenv('KEYS_FOLDER', str(tmp_path))
    app.config['KEYS_FOLDER'] = str(tmp_path)
    app.config['DOWNLOAD_TTL_HOURS'] = 24
    app.config['DOWNLOAD_TTL_SECONDS'] = 24 * 3600

    file_id = 'cafebabecafebabe'
    write_key_file(tmp_path, file_id, b'secret-key-bytes', hours_offset=-1)

    result = get_key_mapping(file_id)
    assert result is not None
    assert 'key' in result
    assert isinstance(result['key'], (bytes, bytearray))
    assert result['original_filename'] == 'secret.txt'