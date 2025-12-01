CREATE OR REPLACE TRIGGER trg_ad_event_alert
AFTER INSERT ON AD_EVENT_LOG
FOR EACH ROW
DECLARE
    v_severity   VARCHAR2(20);
    v_category   VARCHAR2(60);
    v_desc       CLOB;
    v_tactic     VARCHAR2(200);
BEGIN
    v_tactic := LOWER(NVL(:NEW.EVTX_TACTIC, ''));

    -- Mapping tactic names to cyber threat severity
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

    -- Fallback based on EventID (if tactic missing)
    IF v_category IS NULL AND :NEW.EVENT_ID IN (4625,4672,4688,4768,4776) THEN
        v_category := 'Suspicious EventID';
        v_severity := 'MEDIUM';
    END IF;

    -- If detection triggered → store alert
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

BEGIN
  FOR r IN (SELECT EVENT_LOG_ID FROM AD_EVENT_LOG) LOOP
    UPDATE AD_EVENT_LOG SET EVENT_ID = EVENT_ID WHERE EVENT_LOG_ID = r.EVENT_LOG_ID;
  END LOOP;
END;
/

