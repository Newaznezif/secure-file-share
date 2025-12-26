import os
import sys
import pathlib
import io

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from app import app


def test_create_and_use_key(monkeypatch):
    # set admin key in env
    monkeypatch.setenv('API_ADMIN_KEYS', 'adminkey')

    with app.test_client() as c:
        # create key
        r = c.post('/api/keys', headers={'X-API-Key': 'adminkey'})
        assert r.status_code == 200
        data = r.get_json()
        assert 'id' in data and 'key' in data
        key = data['key']

        # use the new key to upload
        upload = c.post('/api/files', data={'file': (io.BytesIO(b'hello'), 'x.txt')}, content_type='multipart/form-data', headers={'X-API-Key': key})
        assert upload.status_code == 200

        # list keys as admin
        r2 = c.get('/api/keys', headers={'X-API-Key': 'adminkey'})
        assert r2.status_code == 200
        lst = r2.get_json()
        assert any(k['id'] == data['id'] for k in lst['keys'])

        # revoke key
        r3 = c.delete(f"/api/keys/{data['id']}", headers={'X-API-Key': 'adminkey'})
        assert r3.status_code == 200

        # key should no longer work
        upload2 = c.post('/api/files', data={'file': (io.BytesIO(b'bye'), 'y.txt')}, content_type='multipart/form-data', headers={'X-API-Key': key})
        assert upload2.status_code == 401
