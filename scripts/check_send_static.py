import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from app import app

with app.test_request_context():
    for fname in ('main.js','style.css'):
        resp = app.send_static_file(fname)
        # response may be in passthrough mode; concatenate iterable
        body = b''
        try:
            body = b''.join(resp.response)
        except Exception:
            try:
                body = resp.get_data()
            except Exception:
                body = b''
        print(fname, 'bytes', len(body))
        # find 'document' occurrences and print windows
        for needle in [b'document', b'dococument', b'navList']:
            i = body.find(needle)
            if i!=-1:
                w = body[i-40:i+40]
                print(needle.decode('ascii',errors='ignore'),'found at',i,'window:', repr(w))
        print('first 400 bytes repr:', repr(body[:400]))
        print('-'*60)
