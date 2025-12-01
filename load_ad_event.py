# load_ad_events.py
import pandas as pd
import cx_Oracle
import json

CSV_PATH = 'evtx_data.csv'  # your file

USER = "system"
PWD = "123"
DSN = "localhost/XE"  # service_name XE

# Load CSV
df = pd.read_csv(CSV_PATH, low_memory=False)

# Safely get column if exists, else empty
def get_val(row, col):
    return row[col] if col in row and pd.notna(row[col]) else None

# Connect to Oracle
conn = cx_Oracle.connect(USER, PWD, DSN)
cur = conn.cursor()

insert_sql = """
INSERT INTO AD_EVENT_LOG (
    EVENT_ID,
    EVENT_RECORD_ID,
    EVENT_TIME_RAW,
    COMPUTER,
    ACCOUNT_NAME,
    SUBJECT_USERNAME,
    TARGET_USERNAME,
    TARGET_USER_SID,
    IP_ADDRESS,
    IP_PORT,
    PROCESS_NAME,
    PROCESS_ID,
    EVTX_FILENAME,
    EVTX_TACTIC,
    AUTH_PACKAGE,
    RAW_JSON
) VALUES (
    :event_id,
    :event_record_id,
    :event_time_raw,
    :computer,
    :account_name,
    :subject_username,
    :target_username,
    :target_user_sid,
    :ip_address,
    :ip_port,
    :process_name,
    :process_id,
    :evtx_filename,
    :evtx_tactic,
    :auth_package,
    :raw_json
)
"""

for _, row in df.iterrows():
    row_dict = row.fillna('').to_dict()
    row_json = json.dumps(row_dict, ensure_ascii=False)

    params = {
        "event_id":          int(row["EventID"]) if "EventID" in row and pd.notna(row["EventID"]) else None,
        "event_record_id":   str(get_val(row, "EventRecordID")),
        "event_time_raw":    str(get_val(row, "TimeCreated")) if "TimeCreated" in row else None,
        "computer":          str(get_val(row, "Computer")),
        "account_name":      str(get_val(row, "AccountName")),
        "subject_username":  str(get_val(row, "SubjectUserName")),
        "target_username":   str(get_val(row, "TargetUserName")),
        "target_user_sid":   str(get_val(row, "TargetUserSid")),
        "ip_address":        str(get_val(row, "IpAddress")),
        "ip_port":           str(get_val(row, "IpPort")),
        "process_name":      str(get_val(row, "ProcessName")),
        "process_id":        str(get_val(row, "ProcessId")),
        "evtx_filename":     str(get_val(row, "EVTX_FileName")),
        "evtx_tactic":       str(get_val(row, "EVTX_Tactic")),
        "auth_package":      str(get_val(row, "AuthenticationPackageName")),
        "raw_json":          row_json
    }

    cur.execute(insert_sql, params)

conn.commit()
cur.close()
conn.close()

print("Loaded", len(df), "rows into AD_EVENT_LOG")
