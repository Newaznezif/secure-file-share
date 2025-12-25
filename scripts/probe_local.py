import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from app import app

paths=['/','/download','/static/main.js','/static/style.css']
with app.test_client() as c:
    for p in paths:
        resp = c.get(p)
        print(p, '->', resp.status_code, 'bytes:', len(resp.get_data()))
        txt = resp.get_data(as_text=True)
        print('snippet:', txt[:200].replace('\n',' '))
        print('-'*60)
