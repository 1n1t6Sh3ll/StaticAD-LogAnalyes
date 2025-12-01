-- package_incident.sql

-- ===============================
-- PACKAGE SPECIFICATION
-- ===============================
CREATE OR REPLACE PACKAGE incident_pkg IS
  PROCEDURE correlate_event(p_event_log_id IN NUMBER);
  PROCEDURE build_incident_batch(p_window_minutes IN NUMBER := 30);
  FUNCTION get_incident_timeline(p_incident_id IN NUMBER) RETURN SYS_REFCURSOR;
  PROCEDURE create_new_incident_for_event(p_event_log_id IN NUMBER);
END incident_pkg;
/
-- ===============================
-- PACKAGE BODY
-- ===============================
CREATE OR REPLACE PACKAGE BODY incident_pkg IS

  PROCEDURE correlate_event(p_event_log_id IN NUMBER) IS
    v_event AD_EVENT_LOG%ROWTYPE;
    v_candidate_incident_id NUMBER;
    v_window_interval INTERVAL DAY TO SECOND := NUMTODSINTERVAL(30,'MINUTE');
    v_next_seq NUMBER;
  BEGIN
    SELECT * INTO v_event FROM AD_EVENT_LOG WHERE EVENT_LOG_ID = p_event_log_id;

    BEGIN
      SELECT INCIDENT_ID INTO v_candidate_incident_id
      FROM INCIDENTS i
      WHERE (i.END_TIME IS NOT NULL AND i.END_TIME >= v_event.EVENT_TIME - v_window_interval)
        AND (
             (v_event.ACCOUNT_NAME IS NOT NULL AND EXISTS (
                 SELECT 1 FROM INCIDENT_EVENTS ie JOIN AD_EVENT_LOG e ON ie.EVENT_LOG_ID=e.EVENT_LOG_ID
                 WHERE ie.INCIDENT_ID = i.INCIDENT_ID AND e.ACCOUNT_NAME = v_event.ACCOUNT_NAME))
          OR (v_event.IP_ADDRESS IS NOT NULL AND EXISTS (
                 SELECT 1 FROM INCIDENT_EVENTS ie JOIN AD_EVENT_LOG e ON ie.EVENT_LOG_ID=e.EVENT_LOG_ID
                 WHERE ie.INCIDENT_ID = i.INCIDENT_ID AND e.IP_ADDRESS = v_event.IP_ADDRESS))
          OR (v_event.COMPUTER IS NOT NULL AND EXISTS (
                 SELECT 1 FROM INCIDENT_EVENTS ie JOIN AD_EVENT_LOG e ON ie.EVENT_LOG_ID=e.EVENT_LOG_ID
                 WHERE ie.INCIDENT_ID = i.INCIDENT_ID AND e.COMPUTER = v_event.COMPUTER))
        )
      AND ROWNUM = 1;
    EXCEPTION
      WHEN NO_DATA_FOUND THEN
        v_candidate_incident_id := NULL;
    END;

    -- if we found one, attach
    IF v_candidate_incident_id IS NOT NULL THEN
      -- compute next sequence
      SELECT NVL(MAX(SEQ_NO),0)+1 INTO v_next_seq
      FROM INCIDENT_EVENTS 
      WHERE INCIDENT_ID = v_candidate_incident_id;

      INSERT INTO INCIDENT_EVENTS (INCIDENT_ID, EVENT_LOG_ID, EVENT_TIME, SEQ_NO)
      VALUES (v_candidate_incident_id, p_event_log_id, v_event.EVENT_TIME, v_next_seq);

      UPDATE INCIDENTS
      SET END_TIME = GREATEST(NVL(END_TIME, v_event.EVENT_TIME), v_event.EVENT_TIME),
          EVENT_COUNT = NVL(EVENT_COUNT,0)+1
      WHERE INCIDENT_ID = v_candidate_incident_id;

      COMMIT;
      RETURN;
    END IF;

  EXCEPTION
    WHEN OTHERS THEN
      INSERT INTO ALERTS (ALERT_TYPE, SEVERITY, DESCRIPTION)
      VALUES ('CorrelationError', 'LOW', 'Error correlating event ' || p_event_log_id || ': ' || SQLERRM);
      COMMIT;
  END correlate_event;

  PROCEDURE create_new_incident_for_event(p_event_log_id IN NUMBER) IS
    v_event AD_EVENT_LOG%ROWTYPE;
    v_title VARCHAR2(400);
    v_description CLOB;
    v_incident_id NUMBER;
  BEGIN
    SELECT * INTO v_event FROM AD_EVENT_LOG WHERE EVENT_LOG_ID = p_event_log_id;

    v_title := 'Incident: ' || NVL(v_event.ACCOUNT_NAME, 'Unknown account') || ' - ' || NVL(v_event.COMPUTER, 'Unknown host');
    v_description := 'Started from event ' || p_event_id || 
                     ' (EventID=' || NVL(TO_CHAR(v_event.EVENT_ID),'N/A') || '). Raw: ' ||
                     DBMS_LOB.SUBSTR(NVL(v_event.RAW_EVENT_JSON, 'none'), 1000, 1);

    INSERT INTO INCIDENTS (START_TIME, END_TIME, TITLE, DESCRIPTION, SEVERITY, EVENT_COUNT)
    VALUES (v_event.EVENT_TIME, v_event.EVENT_TIME, v_title, v_description, 'MEDIUM', 1)
    RETURNING INCIDENT_ID INTO v_incident_id;

    INSERT INTO INCIDENT_EVENTS (INCIDENT_ID, EVENT_LOG_ID, EVENT_TIME, SEQ_NO)
    VALUES (v_incident_id, p_event_log_id, v_event.EVENT_TIME, 1);

    COMMIT;
  END create_new_incident_for_event;

  PROCEDURE build_incident_batch(p_window_minutes IN NUMBER := 30) IS
    CURSOR c_events IS
      SELECT EVENT_LOG_ID, EVENT_TIME, ACCOUNT_NAME, IP_ADDRESS, COMPUTER, EVENT_ID
      FROM AD_EVENT_LOG
      WHERE EVENT_TIME IS NOT NULL
      ORDER BY EVENT_TIME;

    v_curr_incident_id NUMBER := NULL;
    v_window INTERVAL DAY TO SECOND := NUMTODSINTERVAL(p_window_minutes,'MINUTE');
    v_next_seq NUMBER;
    v_last_end_time TIMESTAMP;
  BEGIN
    FOR v_event_rec IN c_events LOOP
      IF v_curr_incident_id IS NULL THEN
        -- start new incident
        INSERT INTO INCIDENTS (START_TIME, END_TIME, TITLE, DESCRIPTION, SEVERITY, EVENT_COUNT)
        VALUES (v_event_rec.EVENT_TIME, v_event_rec.EVENT_TIME, 'Incident starting ' || TO_CHAR(v_event_rec.EVENT_TIME,'YYYY-MM-DD HH24:MI:SS'), 'Auto-created from batch', 'MEDIUM', 1)
        RETURNING INCIDENT_ID INTO v_curr_incident_id;

        INSERT INTO INCIDENT_EVENTS (INCIDENT_ID, EVENT_LOG_ID, EVENT_TIME, SEQ_NO)
        VALUES (v_curr_incident_id, v_event_rec.EVENT_LOG_ID, v_event_rec.EVENT_TIME, 1);

      ELSE
        -- get last end time
        SELECT NVL(END_TIME, v_event_rec.EVENT_TIME) INTO v_last_end_time
        FROM INCIDENTS
        WHERE INCIDENT_ID = v_curr_incident_id;

        IF v_event_rec.EVENT_TIME <= CAST(v_last_end_time AS TIMESTAMP) + v_window
           AND (v_event_rec.ACCOUNT_NAME IS NOT NULL OR v_event_rec.IP_ADDRESS IS NOT NULL OR v_event_rec.COMPUTER IS NOT NULL) THEN

          -- compute next seq
          SELECT NVL(MAX(SEQ_NO),0)+1 INTO v_next_seq
          FROM INCIDENT_EVENTS 
          WHERE INCIDENT_ID = v_curr_incident_id;

          INSERT INTO INCIDENT_EVENTS (INCIDENT_ID, EVENT_LOG_ID, EVENT_TIME, SEQ_NO)
          VALUES (v_curr_incident_id, v_event_rec.EVENT_LOG_ID, v_event_rec.EVENT_TIME, v_next_seq);

          UPDATE INCIDENTS
          SET END_TIME = v_event_rec.EVENT_TIME, EVENT_COUNT = NVL(EVENT_COUNT,0)+1
          WHERE INCIDENT_ID = v_curr_incident_id;

        ELSE
          -- start new incident
          INSERT INTO INCIDENTS (START_TIME, END_TIME, TITLE, DESCRIPTION, SEVERITY, EVENT_COUNT)
          VALUES (v_event_rec.EVENT_TIME, v_event_rec.EVENT_TIME, 'Incident starting ' || TO_CHAR(v_event_rec.EVENT_TIME,'YYYY-MM-DD HH24:MI:SS'), 'Auto-created from batch', 'MEDIUM', 1)
          RETURNING INCIDENT_ID INTO v_curr_incident_id;

          INSERT INTO INCIDENT_EVENTS (INCIDENT_ID, EVENT_LOG_ID, EVENT_TIME, SEQ_NO)
          VALUES (v_curr_incident_id, v_event_rec.EVENT_LOG_ID, v_event_rec.EVENT_TIME, 1);

        END IF;
      END IF;
    END LOOP;

    COMMIT;
  END build_incident_batch;

  FUNCTION get_incident_timeline(p_incident_id IN NUMBER) RETURN SYS_REFCURSOR IS
    rc SYS_REFCURSOR;
  BEGIN
    OPEN rc FOR
      SELECT ie.SEQ_NO, e.EVENT_LOG_ID, e.EVENT_ID, e.EVENT_TIME, e.COMPUTER, e.ACCOUNT_NAME, e.IP_ADDRESS, e.PROCESS_NAME, e.RAW_EVENT_JSON
      FROM INCIDENT_EVENTS ie
      JOIN AD_EVENT_LOG e ON ie.EVENT_LOG_ID = e.EVENT_LOG_ID
      WHERE ie.INCIDENT_ID = p_incident_id
      ORDER BY ie.SEQ_NO;

    RETURN rc;
  END get_incident_timeline;

END incident_pkg;
/
