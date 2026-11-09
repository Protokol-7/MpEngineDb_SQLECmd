import yaml, sqlite3, csv, os, sys, collections
M = yaml.safe_load(open('Windows_MicrosoftDefender_MpEngineDb.smap'))
TOP = {'Description','Author','Email','Id','Version','CSVPrefix','FileName','IdentifyQuery','IdentifyValue','Queries'}
QK = {'Name','Query','BaseFileName','BlobColumns'}
errs = [k for k in M if k not in TOP] + [k for q in M['Queries'] for k in q if k not in QK]
req = [k for k in ('Description','CSVPrefix','Author','Email','Id','Version','FileName','IdentifyQuery','IdentifyValue') if not M.get(k)]
qerr = [q.get('Name') for q in M['Queries'] if not q.get('Query') or not q.get('BaseFileName') or not q.get('Name')]
print('unknown properties:', errs or 'none', '| missing required:', req or 'none', '| bad queries:', qerr or 'none')
print('Version parses as double:', float(M['Version']), '| queries:', len(M['Queries']), '| unique BaseFileNames:', len({q['BaseFileName'] for q in M['Queries']}) == len(M['Queries']))
def header_ok(p): return open(p,'rb').read(8) == b'SQLite f'
os.makedirs('maptest', exist_ok=True)
for label, db in [('lujo', 't/ev/mpenginedb_decrypted.db'), ('cunko', 't/ev_cunko/mpenginedb_decrypted.db'), ('ENCRYPTED original', '/home/claude/ws2/test/ev_cunko/mpenginedb.db')]:
    print('==', label, '| SQLECmd header check passes:', header_ok(db))
    if not header_ok(db): print('   -> SQLECmd would skip this file ("not a SQLite file")'); continue
    c = sqlite3.connect('file:%s?mode=ro' % db, uri=True)
    idv = str(c.execute(M['IdentifyQuery']).fetchone()[0])
    print('   IdentifyQuery ->', idv, '| matches IdentifyValue:', idv == str(M['IdentifyValue']))
    for q in M['Queries']:
        try:
            cur = c.execute(q['Query']); rows = cur.fetchall(); cols = [d[0] for d in cur.description]
            with open('maptest/%s_%s.csv' % (label, q['BaseFileName']), 'w', newline='', encoding='utf-8') as f:
                w = csv.writer(f); w.writerow(cols); w.writerows(rows)
            print('   %-22s rows %5d  cols %2d' % (q['BaseFileName'], len(rows), len(cols)))
        except Exception as e:
            print('   %-22s ERROR %s' % (q['BaseFileName'], e))
