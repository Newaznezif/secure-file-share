from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import sys
import os
ROOT = os.path.dirname(os.path.dirname(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
from app import generate_key, encrypt_file, decrypt_file


def test_encrypt_and_decrypt_gcm():
    key = generate_key()
    plaintext = b'This is a test message' * 50

    enc = encrypt_file(plaintext, key)
    assert enc.startswith(b'GCM1')

    out = decrypt_file(enc, key)
    assert out == plaintext


def test_decrypt_legacy_cbc():
    key = generate_key()
    plaintext = b'Legacy CBC message' * 50

    cipher = AES.new(key, AES.MODE_CBC)
    ct = cipher.encrypt(pad(plaintext, AES.block_size))
    legacy_blob = cipher.iv + ct

    out = decrypt_file(legacy_blob, key)
    assert out == plaintext