import sqlite3
import json

db_path = r'F:\Mydownloads\xtcz10\switch.db'
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row
cur = conn.cursor()

# All rows with non-empty extra, full content
cur.execute("SELECT id, module, display, serverId, extra FROM module_switch WHERE extra IS NOT NULL AND extra != '' ORDER BY module")
rows = cur.fetchall()
print(f'=== Modules with extra config ({len(rows)} total) ===\n')
for r in rows:
    d = dict(r)
    print(f'module={d["module"]} | display={d["display"]} | serverId={d["serverId"]}')
    print(f'  extra: {d["extra"]}')
    print()

# display=1 modules
cur.execute("SELECT module, display, serverId, extra FROM module_switch WHERE display=1 ORDER BY module")
rows2 = cur.fetchall()
print(f'\n=== display=1 modules (enabled/visible, {len(rows2)} total) ===')
for r in rows2:
    extra_str = r['extra'][:60] + '...' if r['extra'] and len(r['extra']) > 60 else (r['extra'] or '')
    print(f'  module={r["module"]:5d} | serverId={r["serverId"]:6d} | extra: {extra_str}')

conn.close()
