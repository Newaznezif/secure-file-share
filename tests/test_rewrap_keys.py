import json
from pathlib import Path
import os
import sys
import tempfile

# ensure scripts module can be found
ROOT = os.path.dirname(os.path.dirname(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from scripts.rewrap_keys_with_master import rewrap_keys


def write_plain_key(folder: Path, file_id: str, key_b64: str):
    data = {
        'enc_key': {'method': 'plain', 'data': key_b64},
        'original_filename': 'secret.txt',
        'timestamp': '2025-01-01T00:00:00'
    }
    p = folder / f"{file_id}.json"
    p.write_text(json.dumps(data))
    return p


def test_rewrap_dry_run(tmp_path):
    keys = tmp_path / 'keys'
    keys.mkdir()
    write_plain_key(keys, 'deadbeefdeadbeef', 'YWJjMTIz')

    changed = rewrap_keys(str(keys), backup_dir=str(tmp_path / 'backup'), master_key='test-master', dry_run=True, save_master=False)
    assert 'deadbeefdeadbeef.json' in changed

    # Ensure file unchanged in dry-run
    data = json.loads((keys / 'deadbeefdeadbeef.json').read_text())
    assert data['enc_key']['method'] == 'plain'


def test_rewrap_apply_and_save_master(tmp_path):
    keys = tmp_path / 'keys'
    keys.mkdir()
    write_plain_key(keys, 'cafebabecafebabe', 'YWJjMTIz')

    env_file = tmp_path / '.env.local'
    changed = rewrap_keys(str(keys), backup_dir=str(tmp_path / 'backup'), master_key='test-master', dry_run=False, save_master=True, env_file=str(env_file))
    assert 'cafebabecafebabe.json' in changed

    data = json.loads((keys / 'cafebabecafebabe.json').read_text())
    assert isinstance(data['enc_key'], dict)
    assert data['enc_key']['method'] == 'gcm'

    # env file should have been written
    assert env_file.exists()
    assert 'MASTER_KEY' in env_file.read_text()