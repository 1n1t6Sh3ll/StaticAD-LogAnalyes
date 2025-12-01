from flask import Flask, render_template, request, jsonify
import cx_Oracle
import math
import json
from datetime import datetime

app = Flask(__name__)

# Database Configuration
USER = "system"
PWD = "123"
DSN = "localhost/XE"

def get_conn():
    """Create and return a database connection"""
    return cx_Oracle.connect(USER, PWD, DSN)

@app.route("/")
def dashboard():
    """Main dashboard with overview statistics"""
    conn = get_conn()
    cur = conn.cursor()
    
    try:
        # Total events and alerts
        cur.execute("SELECT COUNT(*) FROM AD_EVENT_LOG")
        total_events = cur.fetchone()[0]
        
        cur.execute("SELECT COUNT(*) FROM AD_ALERTS")
        total_alerts = cur.fetchone()[0]
        
        # Alerts by category
        cur.execute("""
            SELECT CATEGORY, COUNT(*)
            FROM AD_ALERTS
            GROUP BY CATEGORY
            ORDER BY COUNT(*) DESC
        """)
        alerts_by_cat = cur.fetchall()
        
        # Alerts by risk level
        cur.execute("""
            SELECT RISK_LEVEL, COUNT(*)
            FROM AD_ALERTS
            GROUP BY RISK_LEVEL
            ORDER BY 
                CASE RISK_LEVEL
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    ELSE 4
                END
        """)
        alerts_by_risk = cur.fetchall()
        
        # Top 5 targeted hosts
        cur.execute("""
            SELECT e.COMPUTER, COUNT(*)
            FROM AD_ALERTS a
            JOIN AD_EVENT_LOG e ON a.EVENT_LOG_ID = e.EVENT_LOG_ID
            WHERE e.COMPUTER IS NOT NULL
            GROUP BY e.COMPUTER
            ORDER BY COUNT(*) DESC
            FETCH FIRST 5 ROWS ONLY
        """)
        top_hosts = cur.fetchall()
        
    finally:
        cur.close()
        conn.close()
    
    return render_template(
        "dashboard.html",
        total_events=total_events,
        total_alerts=total_alerts,
        alerts_by_cat=alerts_by_cat,
        alerts_by_risk=alerts_by_risk,
        top_hosts=top_hosts
    )

@app.route("/alerts")
def alerts():
    """Alerts page with filtering and pagination - FIXED"""
    # Get filter parameters
    category = request.args.get("category", "")
    severity = request.args.get("severity", "")
    host = request.args.get("host", "")
    page = int(request.args.get("page", 1))
    page_size = 20
    offset = (page - 1) * page_size
    
    conn = get_conn()
    cur = conn.cursor()
    
    try:
        # Build WHERE clause dynamically
        where_clauses = []
        params = {}
        
        if category:
            where_clauses.append("a.CATEGORY = :cat")
            params["cat"] = category
        if severity:
            where_clauses.append("a.RISK_LEVEL = :sev")
            params["sev"] = severity
        if host:
            where_clauses.append("e.COMPUTER = :host")
            params["host"] = host
        
        where_sql = ""
        if where_clauses:
            where_sql = "WHERE " + " AND ".join(where_clauses)
        
        # Count total with filters
        count_query = f"""
            SELECT COUNT(*)
            FROM AD_ALERTS a
            JOIN AD_EVENT_LOG e ON a.EVENT_LOG_ID = e.EVENT_LOG_ID
            {where_sql}
        """
        
        cur.execute(count_query, params)
        total = cur.fetchone()[0]
        
        # Fetch paginated data with filters
        data_query = f"""
            SELECT
                a.ALERT_ID,
                TO_CHAR(a.ALERT_TIME, 'YYYY-MM-DD HH24:MI:SS'),
                a.SEVERITY,
                a.CATEGORY,
                DBMS_LOB.SUBSTR(a.DESCRIPTION, 200, 1),
                a.EVENT_LOG_ID,
                a.RISK_SCORE,
                a.RISK_LEVEL,
                e.COMPUTER
            FROM AD_ALERTS a
            JOIN AD_EVENT_LOG e ON a.EVENT_LOG_ID = e.EVENT_LOG_ID
            {where_sql}
            ORDER BY a.RISK_SCORE DESC, a.ALERT_TIME DESC
            OFFSET :offset ROWS FETCH NEXT :page_size ROWS ONLY
        """
        
        params["offset"] = offset
        params["page_size"] = page_size
        
        cur.execute(data_query, params)
        rows = cur.fetchall()
        
        # Get filter options
        cur.execute("SELECT DISTINCT CATEGORY FROM AD_ALERTS ORDER BY CATEGORY")
        categories = [r[0] for r in cur.fetchall()]
        
        cur.execute("""
            SELECT DISTINCT RISK_LEVEL 
            FROM AD_ALERTS 
            ORDER BY 
                CASE RISK_LEVEL
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    ELSE 4
                END
        """)
        severities = [r[0] for r in cur.fetchall()]
        
        cur.execute("""
            SELECT DISTINCT COMPUTER
            FROM AD_EVENT_LOG
            WHERE COMPUTER IS NOT NULL
            ORDER BY COMPUTER
        """)
        hosts = [r[0] for r in cur.fetchall()]
        
    finally:
        cur.close()
        conn.close()
    
    total_pages = max(1, math.ceil(total / page_size))
    
    return render_template(
        "alerts.html",
        rows=rows,
        page=page,
        pages=total_pages,
        total=total,
        category=category,
        severity=severity,
        host=host,
        categories=categories,
        severities=severities,
        hosts=hosts
    )

@app.route("/event/<int:eid>")
def event(eid):
    """Detailed event investigation page"""
    conn = get_conn()
    cur = conn.cursor()
    
    try:
        cur.execute("""
            SELECT
                e.EVENT_ID,
                e.EVTX_TACTIC,
                e.COMPUTER,
                e.IP_ADDRESS,
                NVL(a.SEVERITY, 'UNKNOWN'),
                NVL(a.CATEGORY, 'Unknown'),
                TO_CHAR(a.ALERT_TIME, 'YYYY-MM-DD HH24:MI:SS'),
                NVL(a.RISK_SCORE, 0),
                NVL(a.RISK_LEVEL, 'LOW'),
                DBMS_LOB.SUBSTR(e.RAW_JSON, 4000, 1)
            FROM AD_EVENT_LOG e
            LEFT JOIN AD_ALERTS a ON a.EVENT_LOG_ID = e.EVENT_LOG_ID
            WHERE e.EVENT_LOG_ID = :1
              AND ROWNUM = 1
        """, [eid])
        row = cur.fetchone()
        
    finally:
        cur.close()
        conn.close()
    
    if not row:
        return "Event not found", 404
    
    (event_id, tactic, computer, ip,
     severity, category, alert_time,
     risk_score, risk_level, raw_text) = row
    
    # Pretty print JSON
    pretty_json = raw_text
    try:
        obj = json.loads(raw_text)
        pretty_json = json.dumps(obj, indent=2)
    except Exception:
        pass
    
    return render_template(
        "event.html",
        event_log_id=eid,
        severity=severity,
        category=category,
        alert_time=alert_time,
        event_id=event_id,
        tactic=tactic or "Unknown",
        computer=computer or "Unknown",
        ip=ip if ip not in ("", "-", None) else "Unknown",
        risk_score=int(risk_score),
        risk_level=risk_level,
        pretty_json=pretty_json
    )

# 🔥 ONLY THIS ROUTE IS CHANGED: TOP 10 ALERTS FOR THIS HOST
@app.route("/host/<path:hostname>")
def host_view(hostname):
    """Show top 10 alerts related to a specific host, with optional filters"""
    # Optional filters for host view
    severity = request.args.get("severity", "")
    category = request.args.get("category", "")
    
    conn = get_conn()
    cur = conn.cursor()
    
    try:
        # Base WHERE for host
        where_clauses = ["e.COMPUTER = :h"]
        params = {"h": hostname}
        
        if severity:
            where_clauses.append("a.SEVERITY = :sev")
            params["sev"] = severity
        
        if category:
            where_clauses.append("a.CATEGORY = :cat")
            params["cat"] = category
        
        where_sql = " AND ".join(where_clauses)
        
        # Get TOP 10 alerts for this host (by risk score, then time)
        query = f"""
            SELECT
                a.ALERT_ID,
                TO_CHAR(a.ALERT_TIME, 'YYYY-MM-DD HH24:MI:SS'),
                a.SEVERITY,
                a.CATEGORY,
                a.RISK_SCORE,
                a.RISK_LEVEL,
                a.EVENT_LOG_ID
            FROM AD_ALERTS a
            JOIN AD_EVENT_LOG e ON a.EVENT_LOG_ID = e.EVENT_LOG_ID
            WHERE {where_sql}
            ORDER BY a.RISK_SCORE DESC, a.ALERT_TIME DESC
            FETCH FIRST 10 ROWS ONLY
        """
        
        cur.execute(query, params)
        rows = cur.fetchall()
        
        # Filter dropdown options
        cur.execute("SELECT DISTINCT SEVERITY FROM AD_ALERTS ORDER BY SEVERITY")
        severities = [r[0] for r in cur.fetchall()]
        
        cur.execute("SELECT DISTINCT CATEGORY FROM AD_ALERTS ORDER BY CATEGORY")
        categories = [r[0] for r in cur.fetchall()]
        
    finally:
        cur.close()
        conn.close()
    
    return render_template(
        "host.html",
        hostname=hostname,
        rows=rows,
        severity=severity,
        category=category,
        severities=severities,
        categories=categories
    )

@app.route("/ip/<path:ipaddr>")
def ip_view(ipaddr):
    """Show all alerts related to a specific IP"""
    conn = get_conn()
    cur = conn.cursor()
    
    try:
        cur.execute("""
            SELECT
                a.ALERT_ID,
                TO_CHAR(a.ALERT_TIME, 'YYYY-MM-DD HH24:MI:SS'),
                a.SEVERITY,
                a.CATEGORY,
                a.RISK_SCORE,
                a.RISK_LEVEL,
                a.EVENT_LOG_ID,
                e.COMPUTER
            FROM AD_ALERTS a
            JOIN AD_EVENT_LOG e ON a.EVENT_LOG_ID = e.EVENT_LOG_ID
            WHERE e.IP_ADDRESS = :ip
            ORDER BY a.RISK_SCORE DESC, a.ALERT_TIME DESC
        """, [ipaddr])
        rows = cur.fetchall()
        
    finally:
        cur.close()
        conn.close()
    
    return render_template("ip.html", ip=ipaddr, rows=rows)

@app.route("/stats")
def stats():
    """Daily statistics page"""
    conn = get_conn()
    cur = conn.cursor()
    
    try:
        cur.execute("""
                SELECT 
                    TO_CHAR(STATS_DATE, 'YYYY-MM-DD'),
                    TOTAL_EVENTS,
                    TOTAL_ALERTS,
                    TOTAL_LATERAL_MOV,
                    TOTAL_PRIV_ESC,
                    TO_CHAR(GENERATED_AT, 'YYYY-MM-DD HH24:MI:SS')
                FROM AD_DAILY_STATS
                ORDER BY STATS_DATE DESC
            """)

        rows = cur.fetchall()
        
    finally:
        cur.close()
        conn.close()
    
    return render_template("stats.html", rows=rows)

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
