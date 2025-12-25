import pytest
import re
import sys
import pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from app import app

@pytest.fixture
def client():
    with app.test_client() as c:
        yield c


def test_index_contains_quick_demo_and_script(client):
    r = client.get('/')
    assert r.status_code == 200
    txt = r.get_data(as_text=True)
    assert 'id="quickFileId"' in txt
    assert 'id="quickDownload"' in txt
    assert "main.js" in txt


def test_static_assets_are_served_and_contain_expected_strings(client):
    r = client.get('/static/main.js')
    assert r.status_code == 200
    js = r.get_data(as_text=True)

    # confirm the main helpers are present
    assert 'validateAndGo' in js
    assert 'quickDownload' in js
    assert 'quickFileId' in js

    # regex patterns used for validation should be present
    assert re.search(r"\^\[0-9a-fA-F\]\{8,\}\$", js) or re.search(r"0-9a-fA-F", js)

    r2 = client.get('/static/style.css')
    assert r2.status_code == 200
    css = r2.get_data(as_text=True)
    assert ':root' in css or '--accent-1' in css

    # dedicated download stylesheet
    r3 = client.get('/static/download.css')
    assert r3.status_code == 200
    dcss = r3.get_data(as_text=True)
    assert '.download-card' in dcss
    assert '.qr-code' in dcss
    assert '.progress-fill' in dcss


def test_download_of_nonexistent_file_redirects_to_index(client):
    r = client.get('/download/not-a-real-id', follow_redirects=True)
    assert r.status_code == 200
    txt = r.get_data(as_text=True)
    assert 'SecureFile' in txt  # landed back on index
