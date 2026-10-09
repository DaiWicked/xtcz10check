import sqlite3
import sys

db_path = r'H:\xtcz10check\AllToolBox1.4.6\bin\switch.db'
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# 获取所有表
cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = cursor.fetchall()
print("Tables:", tables)

for t in tables:
    table_name = t[0]
    print(f"\n=== {table_name} ===")
    cursor.execute(f"PRAGMA table_info({table_name})")
    columns = cursor.fetchall()
    print("Columns:", [c[1] for c in columns])
    cursor.execute(f"SELECT * FROM {table_name}")
    rows = cursor.fetchall()
    print(f"Row count: {len(rows)}")
    for row in rows:
        print(row)

conn.close()
