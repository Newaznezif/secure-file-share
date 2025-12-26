import json
from click.testing import CliRunner
import os
import uuid

import app as app_mod
import scripts.manage_api_keys as mg


def test_api_key_allows_token_creation_and_rejects_after_revoke(tmp_path, monkeypatch):
    # Use a temporary file for persisted keys
    fp = tmp_path / 'api_keys.json'
    monkeypatch.setattr(app_mod, 'PERSIST_KEYS_FILE', str(fp))

    runner = CliRunner()
    # Create key and show plaintext
    res = runner.invoke(mg.main, ['create', '--show'])
    assert res.exit_code == 0
    lines = [l.strip() for l in res.output.splitlines() if l.strip()]
    key_id = lines[0].split()[-1]
    plaintext = lines[1].split()[-1]

    # Create a dummy key mapping so the endpoint will succeed
    fid = uuid.uuid4().hex
    key_bytes = app_mod.generate_key()
    app_mod.save_key_mapping(fid, key_bytes, 'file.txt')

    client = app_mod.app.test_client()

    # Use the API key to request a token
    r = client.post(f'/api/files/{fid}/token', headers={'X-API-Key': plaintext})
    assert r.status_code == 200
    data = r.get_json()
    assert 'token' in data

    # Revoke via CLI
    r2 = runner.invoke(mg.main, ['revoke', key_id])
    assert r2.exit_code == 0

    # Now the same key should be rejected
    r3 = client.post(f'/api/files/{fid}/token', headers={'X-API-Key': plaintext})
    assert r3.status_code == 401
