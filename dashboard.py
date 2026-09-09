#!/usr/bin/env python3

from flask import Flask, jsonify, render_template
import psycopg2

app = Flask(__name__)

DATABASE = {
    "host": "localhost",
    "port": 5432,
    "database": "windows_detection_db",
    "user": "threat_user",
    "password": "threat_pass_2024"
}


def db():
    return psycopg2.connect(**DATABASE)


@app.route("/")
def index():
    return render_template("index.html")


# ============================================================
# DASHBOARD STATS
# ============================================================

@app.route("/api/stats")
def stats():

    connection = db()
    cursor = connection.cursor()

    cursor.execute(
        "SELECT COUNT(*) FROM sysmon_events"
    )
    events = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM alerts"
    )
    alerts = cursor.fetchone()[0]

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM alerts
        WHERE LOWER(severity)='high'
        """
    )
    high_alerts = cursor.fetchone()[0]

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM alerts
        WHERE status='new'
        """
    )
    new_alerts = cursor.fetchone()[0]

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM cases
        WHERE status='open'
        """
    )
    open_cases = cursor.fetchone()[0]

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM threat_intel_matches
        """
    )
    intel_matches = cursor.fetchone()[0]

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM mitre_mappings
        """
    )
    mitre_count = cursor.fetchone()[0]

    cursor.close()
    connection.close()

    return jsonify({
        "events": events,
        "alerts": alerts,
        "high_alerts": high_alerts,
        "new_alerts": new_alerts,
        "open_cases": open_cases,
        "intel_matches": intel_matches,
        "mitre_count": mitre_count
    })


# ============================================================
# ALERTS
# ============================================================

@app.route("/api/alerts")
def alerts():

    connection = db()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            alert_name,
            severity,
            description,
            rule_name,
            confidence,
            status,
            created_at
        FROM alerts
        ORDER BY id DESC
        LIMIT 100
        """
    )

    columns = [d[0] for d in cursor.description]

    data = [
        dict(zip(columns, row))
        for row in cursor.fetchall()
    ]

    cursor.close()
    connection.close()

    return jsonify(data)


# ============================================================
# CASES
# ============================================================

@app.route("/api/cases")
def cases():

    connection = db()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            case_name,
            priority,
            status,
            assigned_to,
            created_at
        FROM cases
        ORDER BY id DESC
        LIMIT 50
        """
    )

    columns = [d[0] for d in cursor.description]

    data = [
        dict(zip(columns, row))
        for row in cursor.fetchall()
    ]

    cursor.close()
    connection.close()

    return jsonify(data)


# ============================================================
# THREAT INTELLIGENCE
# ============================================================

@app.route("/api/threatintel")
def threatintel():

    connection = db()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            indicator,
            indicator_type,
            threat_name,
            severity,
            matched_value
        FROM threat_intel_matches
        ORDER BY id DESC
        LIMIT 50
        """
    )

    columns = [d[0] for d in cursor.description]

    data = [
        dict(zip(columns, row))
        for row in cursor.fetchall()
    ]

    cursor.close()
    connection.close()

    return jsonify(data)


# ============================================================
# MITRE ATT&CK
# ============================================================

@app.route("/api/mitre")
def mitre():

    connection = db()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            alert_id,
            technique_id,
            technique_name,
            tactic
        FROM mitre_mappings
        ORDER BY id DESC
        LIMIT 50
        """
    )

    columns = [d[0] for d in cursor.description]

    data = [
        dict(zip(columns, row))
        for row in cursor.fetchall()
    ]

    cursor.close()
    connection.close()

    return jsonify(data)


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )
