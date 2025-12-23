import os
import sys
import base64
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import boto3
from botocore.stub import Stubber
from app import protect_key, unprotect_key, save_key_mapping, get_key_mapping


def test_kms_encrypt_decrypt_roundtrip(monkeypatch):
    # Set KMS key id env
    monkeypatch.setenv('AWS_KMS_KEY_ID', 'test-key')

    key_bytes = b'A' * 32

    # Create a real client and stub responses
    client = boto3.client('kms', region_name='us-east-1')
    stubber = Stubber(client)

    # Prepare the fake ciphertext and ensure encrypt returns it
    fake_cipher = b'fakeciphertext'
    stubber.add_response('encrypt', {'CiphertextBlob': fake_cipher}, {'KeyId': 'test-key', 'Plaintext': key_bytes})
    # For decrypt call, return Plaintext
    stubber.add_response('decrypt', {'Plaintext': key_bytes}, {'CiphertextBlob': fake_cipher})
    stubber.activate()

    # Monkeypatch boto3.client to return our stubbed client
    monkeypatch.setattr('boto3.client', lambda *a, **k: client)

    # Use protect_key and unprotect_key
    stored = protect_key(key_bytes)
    assert stored['method'] == 'kms'

    recovered = unprotect_key(stored)
    assert recovered == key_bytes

    stubber.deactivate()


def test_save_and_get_with_kms(monkeypatch, tmp_path):
    # Set KMS key id env
    monkeypatch.setenv('AWS_KMS_KEY_ID', 'test-key')

    key_bytes = b'B' * 32

    client = boto3.client('kms', region_name='us-east-1')
    stubber = Stubber(client)
    fake_cipher = b'fakecipher2'
    stubber.add_response('encrypt', {'CiphertextBlob': fake_cipher}, {'KeyId': 'test-key', 'Plaintext': key_bytes})
    stubber.add_response('decrypt', {'Plaintext': key_bytes}, {'CiphertextBlob': fake_cipher})
    stubber.activate()

    monkeypatch.setattr('boto3.client', lambda *a, **k: client)

    # point KEYS_FOLDER to tmpdir
    from app import app
    orig_keys = app.config['KEYS_FOLDER']
    app.config['KEYS_FOLDER'] = str(tmp_path)

    try:
        fid = 'kmsid1234567890'
        save_key_mapping(fid, key_bytes, 'file.txt')
        kd = get_key_mapping(fid)
        assert kd is not None
        assert kd['original_filename'] == 'file.txt'
        assert kd['key'] == key_bytes
    finally:
        app.config['KEYS_FOLDER'] = orig_keys
        stubber.deactivate()
