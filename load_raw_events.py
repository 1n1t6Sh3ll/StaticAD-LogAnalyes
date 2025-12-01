# load_raw_events.py
import pandas as pd
import cx_Oracle
import json

CSV_PATH = 'evtx_data.csv'   # your CSV file
USER = "system"
PWD = "123"

# Correct Oracle DSN
DSN = cx_Oracle.makedsn("localhost", 1521, service_name="XE")

# Load CSV with low_memory disabled to avoid warnings
df = pd.read_csv(CSV_PATH, low_memory=False)

# Connect to Oracle
conn = cx_Oracle.connect(USER, PWD, DSN)
cur = conn.cursor()

insert_sql = "INSERT INTO AD_RAW_EVENTS (CSV_ROW) VALUES (:1)"

for i, row in df.iterrows():
    # convert row → JSON string
    row_json = row.fillna('').to_json(force_ascii=False)
    cur.execute(insert_sql, [row_json])

conn.commit()
cur.close()
conn.close()

print("✔ Loaded", len(df), "rows into AD_RAW_EVENTS")
