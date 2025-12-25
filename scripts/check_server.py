import ssl
import urllib.request

def probe(path):
    ctx = ssl._create_unverified_context()
    url = f'https://127.0.0.1:5000{path}'
    try:
        resp = urllib.request.urlopen(url, context=ctx, timeout=3)
        data = resp.read().decode('utf-8', errors='replace')
        print(f'OK {path} -> {resp.status} {len(data)} bytes')
        print('snippet:', data[:240].replace('\n',' '))
    except Exception as e:
        print(f'ERR {path} -> {e}')

if __name__ == '__main__':
    for p in ['/', '/download', '/static/main.js', '/static/style.css']:
        probe(p)
