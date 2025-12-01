-- proc_parse_raw.sql
SET SERVEROUTPUT ON
DECLARE
  CURSOR c_raw IS
    SELECT RAW_ID, CSV_ROW FROM AD_RAW_EVENTS WHERE ROWNUM <= 100000; -- adjust or add WHERE LOADED_AT > last_run
  v_json CLOB;
  v_event_record_id VARCHAR2(200);
  v_event_id NUMBER;
  v_time_raw VARCHAR2(4000);
  v_computer VARCHAR2(256);
  v_account VARCHAR2(256);
  v_ip VARCHAR2(128);
  v_proc VARCHAR2(1024);
  v_proc_id VARCHAR2(64);
  v_target VARCHAR2(256);
  v_evtx_file VARCHAR2(256);
  v_evtx_tactic VARCHAR2(128);
  v_auth_pkg VARCHAR2(128);
BEGIN
  FOR r IN c_raw LOOP
    v_json := r.CSV_ROW;
    -- If CSV_ROW is a JSON string created by pandas, use JSON_VALUE to extract fields.
    -- Adjust JSON keys to match what pandas produced (pandas uses column names as keys).
    BEGIN
      v_event_record_id := JSON_VALUE(v_json, '$.EventRecordID' RETURNING VARCHAR2(200));
    EXCEPTION WHEN OTHERS THEN
      v_event_record_id := NULL;
    END;
    BEGIN
      v_event_id := TO_NUMBER(JSON_VALUE(v_json, '$.EventID'));
    EXCEPTION WHEN OTHERS THEN
      v_event_id := NULL;
    END;
    BEGIN
      v_time_raw := JSON_VALUE(v_json, '$.TimeCreated' RETURNING VARCHAR2(4000));
    EXCEPTION WHEN OTHERS THEN
      v_time_raw := JSON_VALUE(v_json, '$.TimeGenerated' RETURNING VARCHAR2(4000));
    END;
    BEGIN
      v_computer := JSON_VALUE(v_json, '$.Computer' RETURNING VARCHAR2(256));
    EXCEPTION WHEN OTHERS THEN
      v_computer := NULL;
    END;
    BEGIN
      v_account := JSON_VALUE(v_json, '$.AccountName' RETURNING VARCHAR2(256));
    EXCEPTION WHEN OTHERS THEN
      v_account := JSON_VALUE(v_json, '$.SubjectUserName' RETURNING VARCHAR2(256));
    END;
    BEGIN
      v_ip := JSON_VALUE(v_json, '$.IpAddress' RETURNING VARCHAR2(128));
    EXCEPTION WHEN OTHERS THEN
      v_ip := NULL;
    END;
    BEGIN
      v_proc := JSON_VALUE(v_json, '$.ProcessName' RETURNING VARCHAR2(1024));
    EXCEPTION WHEN OTHERS THEN
      v_proc := NULL;
    END;
    BEGIN
      v_proc_id := JSON_VALUE(v_json, '$.ProcessId' RETURNING VARCHAR2(64));
    EXCEPTION WHEN OTHERS THEN
      v_proc_id := NULL;
    END;
    BEGIN
      v_target := JSON_VALUE(v_json, '$.TargetUserName' RETURNING VARCHAR2(256));
    EXCEPTION WHEN OTHERS THEN
      v_target := NULL;
    END;
    BEGIN
      v_evtx_file := JSON_VALUE(v_json, '$.EVTX_FileName' RETURNING VARCHAR2(256));
    EXCEPTION WHEN OTHERS THEN
      v_evtx_file := NULL;
    END;
    BEGIN
      v_evtx_tactic := JSON_VALUE(v_json, '$.EVTX_Tactic' RETURNING VARCHAR2(128));
    EXCEPTION WHEN OTHERS THEN
      v_evtx_tactic := NULL;
    END;
    BEGIN
      v_auth_pkg := JSON_VALUE(v_json, '$.AuthenticationPackageName' RETURNING VARCHAR2(128));
    EXCEPTION WHEN OTHERS THEN
      v_auth_pkg := NULL;
    END;

    INSERT INTO AD_EVENT_LOG (
      EVENT_RECORD_ID, EVENT_ID, EVENT_TIME_RAW, COMPUTER, ACCOUNT_NAME,
      IP_ADDRESS, PROCESS_NAME, PROCESS_ID, TARGET_USERNAME, EVTX_FILENAME, EVTX_TACTIC, AUTH_PACKAGE, RAW_EVENT_JSON
    ) VALUES (
      v_event_record_id, v_event_id, v_time_raw, v_computer, v_account,
      v_ip, v_proc, v_proc_id, v_target, v_evtx_file, v_evtx_tactic, v_auth_pkg, v_json
    );
    -- Optionally delete the raw row after success
    -- DELETE FROM AD_RAW_EVENTS WHERE RAW_ID = r.RAW_ID;
  END LOOP;
  COMMIT;
  DBMS_OUTPUT.put_line('Parsed raw events into AD_EVENT_LOG.');
END;
/
