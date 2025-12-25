import pytest
from datetime import datetime
from app import app

@pytest.fixture
def client():
    with app.test_client() as c:
        yield c


def test_now_in_template(client):
    resp = client.get('/')
    assert resp.status_code == 200
    assert str(datetime.utcnow().year) in resp.get_data(as_text=True)
