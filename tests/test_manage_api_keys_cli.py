import json
from click.testing import CliRunner
import os

import app as app_mod
import scripts.manage_api_keys as mg


def test_create_list_and_revoke(tmp_path, monkeypatch):
    # Use a temporary file for persisted keys
    fp = tmp_path / 'api_keys.json'
    monkeypatch.setattr(app_mod, 'PERSIST_KEYS_FILE', str(fp))

    runner = CliRunner()

    # Create a key and show plaintext
    result = runner.invoke(mg.main, ['create', '--show'])
    assert result.exit_code == 0
    out = result.output
    assert 'Created API key id:' in out
    assert 'API key (save this now):' in out

    # Extract id and plaintext key
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    key_id = lines[0].split()[-1]
    plaintext = lines[1].split()[-1]

    # The plaintext should validate as an API key
    assert app_mod._is_valid_api_key(plaintext)

    # List should show the id
    result = runner.invoke(mg.main, ['list'])
    assert result.exit_code == 0
    assert key_id in result.output

    # Revoke the key
    result = runner.invoke(mg.main, ['revoke', key_id])
    assert result.exit_code == 0
    assert f'Key {key_id} revoked.' in result.output

    # Persisted file should mark revoked
    data = json.loads(fp.read_text())
    recs = [r for r in data if r['id'] == key_id]
    assert len(recs) == 1
    assert recs[0].get('revoked') is True

    # Plaintext key should no longer validate
    assert not app_mod._is_valid_api_key(plaintext)


def test_revoke_unknown_id(tmp_path, monkeypatch):
    fp = tmp_path / 'api_keys.json'
    monkeypatch.setattr(app_mod, 'PERSIST_KEYS_FILE', str(fp))

    runner = CliRunner()
    result = runner.invoke(mg.main, ['revoke', 'nonexistent'])
    assert result.exit_code == 0
    assert 'Key id nonexistent not found.' in result.output


def test_create_without_show(tmp_path, monkeypatch):
    fp = tmp_path / 'api_keys.json'
    monkeypatch.setattr(app_mod, 'PERSIST_KEYS_FILE', str(fp))

    runner = CliRunner()
    result = runner.invoke(mg.main, ['create'])
    assert result.exit_code == 0
    assert 'Run with --show to print the plaintext key.' in result.output
