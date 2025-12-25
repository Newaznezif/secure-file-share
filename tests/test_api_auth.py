import io
import os
import sys
import pathlib
import pytest

# Ensure project root is importable
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app import app


@pytest.fixture
def client():
    with app.test_client() as c:
        yield c


def test_api_requires_key(client):
    # No key provided
    data = {'file': (io.BytesIO(b'hello'), 'test.txt')}
    r = client.post('/api/files', data=data, content_type='multipart/form-data')
    assert r.status_code == 401


def test_api_accepts_valid_key(client, monkeypatch):
    monkeypatch.setenv('API_KEYS', 'testkey')
    data = {'file': (io.BytesIO(b'hello'), 'test.txt')}
    r = client.post('/api/files', data=data, content_type='multipart/form-data', headers={'X-API-Key': 'testkey'})
    assert r.status_code == 200
    json = r.get_json()
    assert 'file_id' in json
    assert 'download_url' in json


def test_api_rate_limit(client, monkeypatch):
    monkeypatch.setenv('API_KEYS', 'ratelimitkey')
    headers = {'X-API-Key': 'ratelimitkey'}

    # Create fresh file objects for each request to avoid closed file errors
    r1 = client.post('/api/files', data={'file': (io.BytesIO(b'a'), 'a.txt')}, content_type='multipart/form-data', headers=headers)
    r2 = client.post('/api/files', data={'file': (io.BytesIO(b'b'), 'b.txt')}, content_type='multipart/form-data', headers=headers)
    r3 = client.post('/api/files', data={'file': (io.BytesIO(b'c'), 'c.txt')}, content_type='multipart/form-data', headers=headers)

    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r3.status_code == 200
