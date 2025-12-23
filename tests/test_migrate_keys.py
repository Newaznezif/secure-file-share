import os
import sys
import json
import base64
from pathlib import Path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import boto3
from botocore.stub import Stubber
from scripts.migrate_keys_to_kms import migrate_keys


def make_plain_keyfile(folder, name, key_bytes):
    data = {
        'enc_key': {
            'method': 'plain',
            'data': base64.b64encode(key_bytes).decode('utf-8')
        },
        'original_filename': 'file.dat'
    }
    p = Path(folder) / name
    p.write_text(json.dumps(data))
    return p


def test_migrate_keys_with_kms(monkeypatch, tmp_path):
    # Prepare key file
    keys_dir = tmp_path / 'keys'
    keys_dir.mkdir()
    key_bytes = b'X' * 32
    make_plain_keyfile(keys_dir, 'k1.json', key_bytes)

    # Prepare stubbed KMS client
    client = boto3.client('kms', region_name='us-east-1')
    stubber = Stubber(client)
    fake_cipher = b'ciphertext-migrate'
    # encrypt then decrypt (script uses only encrypt)
    stubber.add_response('encrypt', {'CiphertextBlob': fake_cipher}, {'KeyId': 'test', 'Plaintext': key_bytes})
    stubber.activate()

    monkeypatch.setenv('AWS_KMS_KEY_ID', 'test')
    monkeypatch.setattr('boto3.client', lambda *a, **k: client)

    # Run dry-run
    changed_dry = migrate_keys(str(keys_dir), dry_run=True)
    assert 'k1.json' in changed_dry

    # Run actual migration
    changed = migrate_keys(str(keys_dir), dry_run=False)
    assert 'k1.json' in changed

    # verify file updated
    data = json.loads((keys_dir / 'k1.json').read_text())
    assert data['enc_key']['method'] == 'kms'
    assert isinstance(data['enc_key']['data'], str)

    stubber.deactivate()
