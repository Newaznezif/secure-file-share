from pathlib import Path
p = Path(__file__).resolve().parent.parent / 'static'
for fname in ('main.js','style.css'):
    path = p / fname
    data = path.read_bytes()
    print(fname, 'disk bytes', len(data))
    print('repr snippet:', repr(data[:200]))
    print('-'*60)