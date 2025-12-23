import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from dotenv import load_dotenv
from app import _get_master_key


def test_dotenv_loads_master_key(tmp_path, monkeypatch):
    # Create a temporary .env file with MASTER_KEY
    env_file = tmp_path / '.env'
    env_file.write_text('MASTER_KEY=dot-env-test-key')

    # Load that dotenv and assert _get_master_key reads it
    load_dotenv(str(env_file))
    mk = _get_master_key()
    assert mk is not None
    assert len(mk) == 32
