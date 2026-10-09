import sqlite3
import json

db_path = r'F:\Mydownloads\xtcz10\switch.db'
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row
cur = conn.cursor()

# android_metadata
print('=== android_metadata ===')
cur.execute('SELECT * FROM android_metadata')
for r in cur.fetchall():
    print(dict(r))
print()

# sqlite_sequence
print('=== sqlite_sequence ===')
cur.execute('SELECT * FROM sqlite_sequence')
for r in cur.fetchall():
    print(dict(r))
print()

# module_switch - all rows
print('=== module_switch (all 434 rows) ===')
cur.execute('SELECT id, module, display, serverId, tips, extra FROM module_switch ORDER BY module')
rows = cur.fetchall()
for r in rows:
    d = dict(r)
    # Truncate long extra for display
    extra = d.get('extra') or ''
    if len(extra) > 120:
        d['extra'] = extra[:120] + '...'
    print(json.dumps(d, ensure_ascii=False))

print(f'\nTotal rows: {len(rows)}')

# Analyze distinct values
print('\n=== display value distribution ===')
cur.execute('SELECT display, COUNT(*) as cnt FROM module_switch GROUP BY display ORDER BY cnt DESC')
for r in cur.fetchall():
    print(f'  display={r[0]}: {r[1]} rows')

print('\n=== serverId value distribution ===')
cur.execute('SELECT serverId, COUNT(*) as cnt FROM module_switch GROUP BY serverId ORDER BY cnt DESC')
for r in cur.fetchall():
    print(f'  serverId={r[0]}: {r[1]} rows')

print('\n=== tips non-empty count ===')
cur.execute("SELECT COUNT(*) FROM module_switch WHERE tips IS NOT NULL AND tips != ''")
print(f'  {cur.fetchone()[0]} rows have tips')

print('\n=== extra non-empty count ===')
cur.execute("SELECT COUNT(*) FROM module_switch WHERE extra IS NOT NULL AND extra != ''")
print(f'  {cur.fetchone()[0]} rows have extra')

conn.close()
