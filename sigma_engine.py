#!/usr/bin/env python3

import os
import yaml
import psycopg2


DATABASE = {
    "host": "localhost",
    "port": 5432,
    "database": "windows_detection_db",
    "user": "threat_user",
    "password": "threat_pass_2024"
}


SIGMA_DIRECTORY = "sigma_rules"


def db():
    return psycopg2.connect(**DATABASE)


def load_sigma_rules():

    rules = []

    for filename in os.listdir(SIGMA_DIRECTORY):

        if not filename.endswith(".yml"):
            continue

        path = os.path.join(
            SIGMA_DIRECTORY,
            filename
        )

        with open(path, "r") as file:

            rule = yaml.safe_load(file)

            rules.append(rule)

    return rules


def create_sigma_alert(
    cursor,
    event_id,
    rule
):

    cursor.execute(
        """
        INSERT INTO sigma_alerts
        (
            event_id,
            rule_title,
            rule_id,
            level,
            description,
            event_data
        )
        VALUES
        (
            %s,%s,%s,%s,%s,%s
        )
        """,
        (
            event_id,
            rule.get("title"),
            rule.get("id"),
            rule.get("level"),
            rule.get("description"),
            "Sigma Match"
        )
    )


def run_sigma_engine():

    print("=" * 60)
    print("SIGMA DETECTION ENGINE")
    print("=" * 60)

    connection = db()
    cursor = connection.cursor()

    rules = load_sigma_rules()

    print(
        f"[+] Sigma Rules Loaded: {len(rules)}"
    )

    cursor.execute(
        """
        SELECT
            id,
            image,
            command_line
        FROM sysmon_events
        """
    )

    events = cursor.fetchall()

    matches = 0

    for event in events:

        event_id = event[0]

        image = str(event[1] or "").lower()

        command_line = str(event[2] or "").lower()

        for rule in rules:

            detection = rule.get(
                "detection",
                {}
            )

            keywords = detection.get(
                "keywords",
                []
            )

            for keyword in keywords:

                keyword = keyword.lower()

                if (
                    keyword in image
                    or keyword in command_line
                ):

                    create_sigma_alert(
                        cursor,
                        event_id,
                        rule
                    )

                    matches += 1

                    break

    connection.commit()

    print(
        f"[+] Sigma Matches Found: {matches}"
    )

    cursor.close()
    connection.close()


if __name__ == "__main__":
    run_sigma_engine()
