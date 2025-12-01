CREATE OR REPLACE TRIGGER trg_ad_event_alert
AFTER INSERT OR UPDATE ON AD_EVENT_LOG
FOR EACH ROW
DECLARE
    v_severity   VARCHAR2(20);
    v_category   VARCHAR2(60);
    v_desc       CLOB;
    v_tactic     VARCHAR2(200);
BEGIN
    v_tactic := LOWER(NVL(:NEW.EVTX_TACTIC, ''));

    IF v_tactic = 'lateral movement' THEN
        v_category := 'Lateral Movement';
        v_severity := 'CRITICAL';
    ELSIF v_tactic = 'privilege escalation' THEN
        v_category := 'Privilege Escalation';
        v_severity := 'HIGH';
    ELSIF v_tactic = 'credential access' THEN
        v_category := 'Credential Access';
        v_severity := 'HIGH';
    ELSIF v_tactic = 'persistence' THEN
        v_category := 'Persistence';
        v_severity := 'MEDIUM';
    ELSIF v_tactic = 'execution' THEN
        v_category := 'Execution';
        v_severity := 'MEDIUM';
    ELSIF v_tactic = 'defense evasion' THEN
        v_category := 'Defense Evasion';
        v_severity := 'MEDIUM';
    ELSIF v_tactic = 'command and control' THEN
        v_category := 'Command and Control';
        v_severity := 'HIGH';
    END IF;

    -- fallback if tactic missing
    IF v_category IS NULL AND :NEW.EVENT_ID IN (4625,4672,4688,4768,4776) THEN
        v_category := 'Suspicious EventID';
        v_severity := 'MEDIUM';
    END IF;

    IF v_category IS NOT NULL THEN
        v_desc :=
            'EventID=' || NVL(TO_CHAR(:NEW.EVENT_ID),'?') ||
            ', User=' || NVL(:NEW.ACCOUNT_NAME, :NEW.TARGET_USERNAME) ||
            ', Host=' || NVL(:NEW.COMPUTER,'?') ||
            ', IP=' || NVL(:NEW.IP_ADDRESS,'?') ||
            ', Tactic=' || NVL(:NEW.EVTX_TACTIC,'?');

        INSERT INTO AD_ALERTS (EVENT_LOG_ID, SEVERITY, CATEGORY, DESCRIPTION)
        VALUES (:NEW.EVENT_LOG_ID, v_severity, v_category, v_desc);
    END IF;
END;
/

 -- This forces the trigger to fire again for all rows.

BEGIN
  FOR r IN (SELECT EVENT_LOG_ID FROM AD_EVENT_LOG) LOOP
    UPDATE AD_EVENT_LOG
    SET EVTX_TACTIC = EVTX_TACTIC
    WHERE EVENT_LOG_ID = r.EVENT_LOG_ID;
  END LOOP;
END;
/

-- Cursor-based PL/SQL procedure for daily stats
CREATE OR REPLACE PROCEDURE AD_BUILD_DAILY_STATS AS
    CURSOR c_events (p_day DATE) IS
        SELECT EVENT_ID, EVTX_TACTIC
        FROM AD_EVENT_LOG
        WHERE TRUNC(CREATED_AT) = p_day;

    v_day              DATE := TRUNC(SYSDATE);
    v_total            NUMBER := 0;
    v_total_alerts     NUMBER := 0;
    v_total_lat_mov    NUMBER := 0;
    v_total_priv_esc   NUMBER := 0;

    v_evt c_events%ROWTYPE;
BEGIN
    -- Count alerts separately
    SELECT COUNT(*) INTO v_total_alerts
    FROM AD_ALERTS
    WHERE TRUNC(ALERT_TIME) = v_day;

    -- Scan events with cursor
    FOR v_evt IN c_events(v_day) LOOP
        v_total := v_total + 1;

        IF v_evt.EVTX_TACTIC = 'Lateral Movement' THEN
            v_total_lat_mov := v_total_lat_mov + 1;
        ELSIF v_evt.EVTX_TACTIC = 'Privilege Escalation' THEN
            v_total_priv_esc := v_total_priv_esc + 1;
        END IF;
    END LOOP;

    MERGE INTO AD_DAILY_STATS d
    USING (SELECT v_day AS stats_date FROM dual) s
    ON (d.STATS_DATE = s.stats_date)
    WHEN MATCHED THEN
        UPDATE SET TOTAL_EVENTS       = v_total,
                   TOTAL_ALERTS       = v_total_alerts,
                   TOTAL_LATERAL_MOV  = v_total_lat_mov,
                   TOTAL_PRIV_ESC     = v_total_priv_esc,
                   GENERATED_AT       = SYSDATE
    WHEN NOT MATCHED THEN
        INSERT (STATS_DATE, TOTAL_EVENTS, TOTAL_ALERTS,
                TOTAL_LATERAL_MOV, TOTAL_PRIV_ESC, GENERATED_AT)
        VALUES (v_day, v_total, v_total_alerts,
                v_total_lat_mov, v_total_priv_esc, SYSDATE);
END;
/

--to run:
BEGIN
  AD_BUILD_DAILY_STATS;
END;
/

-- ALL outputs

SELECT * FROM AD_ALERTS ORDER BY ALERT_TIME DESC FETCH FIRST 10 ROWS ONLY;
SELECT * FROM AD_DAILY_STATS ORDER BY STATS_DATE;
