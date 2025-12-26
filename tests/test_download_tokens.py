import io
import os
import sys
import pathlib
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from app import app, create_download_token, verify_download_token


def test_token_roundtrip(monkeypatch):
    monkeypatch.setenv('API_KEYS', 'tk')
    with app.test_client() as c:
        # upload via api
        r = c.post('/api/files', data={'file': (io.BytesIO(b'hello world'), 'hm.txt')}, content_type='multipart/form-data', headers={'X-API-Key': 'tk'})
        assert r.status_code == 200
        file_id = r.get_json()['file_id']

        # create token
        r2 = c.post(f'/api/files/{file_id}/token', headers={'X-API-Key': 'tk'})
        assert r2.status_code == 200
        tok = r2.get_json()['token']

        # download via token
        r3 = c.get(f'/download/token/{tok}')
        assert r3.status_code == 200
        assert r3.get_data() == b'hello world'


def test_expired_token(monkeypatch):
    # create token with negative TTL
    tok = create_download_token('deadbeefdeadbeef', ttl=-10)
    try:
        verify_download_token(tok)
        assert False, 'expected expired'
    except ValueError as e:
        assert 'expired' in str(e).lower()


def test_invalid_token():
    with app.test_client() as c:
        r = c.get('/download/token/not-a-token')
        # should redirect to index
        assert r.status_code in (302, 301, 200)
