import os
import base64
import sys
# ensure project root is on path for imports when running tests
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app import protect_key, unprotect_key, _get_master_key, save_key_mapping, get_key_mapping, generate_key


def test_protect_unprotect_roundtrip(monkeypatch, tmp_path):
    # ensure MASTER_KEY is set for the test
    monkeypatch.setenv('MASTER_KEY', 'test-master-secret')
    mk = _get_master_key()
    assert mk is not None

    key = generate_key()
    wrapped = protect_key(key)
    assert isinstance(wrapped, dict)

    unwrapped = unprotect_key(wrapped)
    assert unwrapped == key


def test_save_and_get_key_mapping(tmp_path, monkeypatch):
    # point KEYS_FOLDER to tmpdir to avoid touching repo
    monkeypatch.setenv('MASTER_KEY', 'another-test-secret')
    os.environ['MASTER_KEY'] = 'another-test-secret'

    # override app config path
    from app import app
    orig_keys = app.config['KEYS_FOLDER']
    app.config['KEYS_FOLDER'] = str(tmp_path)

    try:
        key = generate_key()
        file_id = 'testid1234567890'
        filename = 'secret.txt'
        save_key_mapping(file_id, key, filename)

        kd = get_key_mapping(file_id)
        assert kd is not None
        assert kd['original_filename'] == filename
        assert 'key' in kd
        assert kd['key'] == key
    finally:
        app.config['KEYS_FOLDER'] = orig_keys
