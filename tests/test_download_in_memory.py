import os
import sys
# ensure project root is on path for imports when running tests
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app import app, generate_key, encrypt_file, save_key_mapping


def test_download_serves_data_in_memory(tmp_path, monkeypatch):
    # Setup test upload folder and keys folder
    from app import app as flask_app
    orig_upload = flask_app.config['UPLOAD_FOLDER']
    orig_keys = flask_app.config['KEYS_FOLDER']
    flask_app.config['UPLOAD_FOLDER'] = str(tmp_path)
    flask_app.config['KEYS_FOLDER'] = str(tmp_path)

    # Set master key env for wrapping
    monkeypatch.setenv('MASTER_KEY', 'download-test-master')

    try:
        client = flask_app.test_client()

        filename = 'hello.txt'
        file_data = b'Hello secure world!'

        # generate key and encrypt file
        key = generate_key()
        encrypted = encrypt_file(file_data, key)
        file_id = 'dltest1234567890'

        # write encrypted file
        enc_path = os.path.join(flask_app.config['UPLOAD_FOLDER'], f'{file_id}.enc')
        with open(enc_path, 'wb') as f:
            f.write(encrypted)

        # save mapping
        save_key_mapping(file_id, key, filename)

        # request download
        r = client.get(f'/download/{file_id}')
        assert r.status_code == 200
        # content should match original
        assert r.data == file_data
        # content-disposition filename should match filename
        assert 'attachment' in r.headers.get('Content-Disposition', '')
        assert filename in r.headers.get('Content-Disposition', '')
    finally:
        flask_app.config['UPLOAD_FOLDER'] = orig_upload
        flask_app.config['KEYS_FOLDER'] = orig_keys
