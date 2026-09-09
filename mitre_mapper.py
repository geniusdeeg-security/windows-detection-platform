#!/usr/bin/env python3

import psycopg2

DATABASE = {
    "host": "localhost",
    "port": 5432,
    "database": "windows_detection_db",
    "user": "threat_user",
    "password": "threat_pass_2024"
}


MITRE_RULES = {

    "PowerShell Execution": {
        "technique_id": "T1059.001",
        "technique_name": "PowerShell",
        "tactic": "Execution"
    },

    "Suspicious PowerShell Encoded Command": {
        "technique_id": "T1059.001",
        "technique_name": "PowerShell",
        "tactic": "Execution"
    },

    "Command Shell Execution": {
        "technique_id": "T1059.003",
        "technique_name": "Windows Command Shell",
        "tactic": "Execution"
    },

    "Registry Run Key Modification": {
        "technique_id": "T1547.001",
        "technique_name": "Registry Run Keys / Startup Folder",
        "tactic": "Persistence"
    },

    "Registry Run Key Creation": {
        "technique_id": "T1547.001",
        "technique_name": "Registry Run Keys / Startup Folder",
        "tactic": "Persistence"
    },

    "PowerShell Network Connection": {
        "technique_id": "T1105",
        "technique_name": "Ingress Tool Transfer",
        "tactic": "Command and Control"
    },

    "External Network Connection": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "Command and Control"
    },

    "Process Access Detection": {
        "technique_id": "T1003.001",
        "technique_name": "LSASS Memory",
        "tactic": "Credential Access"
    }

}


def connect_db():

    return psycopg2.connect(**DATABASE)


def mapping_exists(cursor, alert_id):

    cursor.execute(
        """
        SELECT id
        FROM mitre_mappings
        WHERE alert_id = %s
        LIMIT 1
        """,
        (alert_id,)
    )

    return cursor.fetchone() is not None


def main():

    print("=" * 60)
    print("MITRE ATT&CK MAPPING ENGINE")
    print("=" * 60)

    connection = connect_db()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            rule_name
        FROM alerts
        """
    )

    alerts = cursor.fetchall()

    created = 0

    for alert_id, rule_name in alerts:

        if mapping_exists(cursor, alert_id):
            continue

        if rule_name not in MITRE_RULES:
            continue

        mitre = MITRE_RULES[rule_name]

        cursor.execute(
            """
            INSERT INTO mitre_mappings
            (
                alert_id,
                technique_id,
                technique_name,
                tactic,
                description
            )
            VALUES
            (
                %s,
                %s,
                %s,
                %s,
                %s
            )
            """,
            (
                alert_id,
                mitre["technique_id"],
                mitre["technique_name"],
                mitre["tactic"],
                rule_name
            )
        )

        created += 1

    connection.commit()

    cursor.close()
    connection.close()

    print(f"[+] MITRE mappings created: {created}")


if __name__ == "__main__":
    main()
