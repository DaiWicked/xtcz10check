import sqlite3
import sys

db_path = r'F:\Mydownloads\xtcz10\switch.db'
conn = sqlite3.connect(db_path)
cur = conn.cursor()

# List all tables
cur.execute("SELECT name, type FROM sqlite_master WHERE type IN ('table','view') ORDER BY name")
tables = cur.fetchall()
print('=== Tables/Views ===')
for t in tables:
    print(f'  {t[1]}: {t[0]}')
print()

for t in tables:
    if t[1] == 'table':
        cur.execute(f"SELECT sql FROM sqlite_master WHERE name='{t[0]}'")
        schema = cur.fetchone()
        print(f'=== Schema: {t[0]} ===')
        print(schema[0] if schema else 'N/A')
        print()
        cur.execute(f'SELECT COUNT(*) FROM "{t[0]}"')
        cnt = cur.fetchone()[0]
        print(f'  Row count: {cnt}')
        print()

conn.close()
