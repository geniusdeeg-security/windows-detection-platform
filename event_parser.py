#!/usr/bin/env python3

import os
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

import psycopg2
from Evtx.Evtx import Evtx


# ============================================================
# PROJECT 2: WINDOWS DETECTION PLATFORM
# EVTX -> PostgreSQL Event Parser
# ============================================================

DATABASE = {
    "host": "localhost",
    "port": 5432,
    "database": "windows_detection_db",
    "user": "threat_user",
    "password": "threat_pass_2024"
}

INPUT_FILE = "logs/sysmon_project2.evtx"

EVENT_NS = {
    "e": "http://schemas.microsoft.com/win/2004/08/events/event"
}


# ============================================================
# XML HELPERS
# ============================================================

def get_event_data(root):
    """
    Convert Sysmon EventData XML into a Python dictionary.
    """

    data = {}

    for item in root.findall("./e:EventData/e:Data", EVENT_NS):

        name = item.attrib.get("Name")

        if name:
            data[name] = item.text

    return data


def get_value(data, *names):
    """
    Return the first available non-empty value.
    """

    for name in names:

        value = data.get(name)

        if value is not None and value != "":
            return value

    return None


def convert_integer(value):
    """
    Safely convert a value to integer.
    """

    if value is None or value == "":
        return None

    try:

        return int(value)

    except (ValueError, TypeError):

        return None


def convert_timestamp(value):
    """
    Convert Sysmon UTC timestamp into a PostgreSQL-compatible
    timestamp object.
    """

    if not value:
        return None

    try:

        value = value.strip()

        if value.endswith("Z"):

            value = value[:-1] + "+00:00"

        # ----------------------------------------------------
        # Normalize fractional seconds.
        # Python supports a maximum of 6 digits.
        # Sysmon may provide 7 digits.
        # ----------------------------------------------------

        if "." in value:

            before, after = value.split(".", 1)

            timezone_part = ""

            if "+" in after:

                fraction, timezone_part = after.split("+", 1)

                timezone_part = "+" + timezone_part

            elif "-" in after:

                fraction, timezone_part = after.split("-", 1)

                timezone_part = "-" + timezone_part

            else:

                fraction = after

            fraction = fraction[:6]

            value = (
                before
                + "."
                + fraction
                + timezone_part
            )

        parsed = datetime.fromisoformat(value)

        if parsed.tzinfo is None:

            parsed = parsed.replace(
                tzinfo=timezone.utc
            )

        return parsed

    except Exception:

        return None


# ============================================================
# SYSMON EVENT PARSER
# ============================================================

def parse_event(xml):
    """
    Parse one Sysmon XML event into the database structure.
    """

    root = ET.fromstring(xml)

    # ========================================================
    # SYSTEM SECTION
    # ========================================================

    event_id_element = root.find(
        "./e:System/e:EventID",
        EVENT_NS
    )

    computer_element = root.find(
        "./e:System/e:Computer",
        EVENT_NS
    )

    time_element = root.find(
        "./e:System/e:TimeCreated",
        EVENT_NS
    )

    if event_id_element is None:

        return None

    event_id = convert_integer(
        event_id_element.text
    )

    computer_name = None

    if computer_element is not None:

        computer_name = computer_element.text

    event_time = None

    if time_element is not None:

        event_time = convert_timestamp(
            time_element.attrib.get("SystemTime")
        )

    # ========================================================
    # EVENT DATA SECTION
    # ========================================================

    data = get_event_data(root)

    # ========================================================
    # COMMON PROCESS FIELDS
    # ========================================================

    user_name = get_value(
        data,
        "User",
        "UserName",
        "SubjectUserName",
        "TargetUserName"
    )

    process_guid = get_value(
        data,
        "ProcessGuid"
    )

    process_id = convert_integer(
        get_value(
            data,
            "ProcessId"
        )
    )

    image = get_value(
        data,
        "Image"
    )

    command_line = get_value(
        data,
        "CommandLine"
    )

    parent_image = get_value(
        data,
        "ParentImage"
    )

    parent_command_line = get_value(
        data,
        "ParentCommandLine"
    )

    # ========================================================
    # NETWORK FIELDS - EVENT ID 3
    # ========================================================

    source_ip = get_value(
        data,
        "SourceIp",
        "SourceIP"
    )

    source_port = convert_integer(
        get_value(
            data,
            "SourcePort"
        )
    )

    destination_ip = get_value(
        data,
        "DestinationIp",
        "DestinationIP"
    )

    destination_port = convert_integer(
        get_value(
            data,
            "DestinationPort"
        )
    )

    protocol = get_value(
        data,
        "Protocol"
    )

    # ========================================================
    # DNS FIELDS - EVENT ID 22
    # ========================================================

    dns_query = get_value(
        data,
        "QueryName"
    )

    dns_query_status = convert_integer(
        get_value(
            data,
            "QueryStatus"
        )
    )

    # ========================================================
    # FILE / REGISTRY FIELDS
    # ========================================================

    target_object = get_value(
        data,
        "TargetFilename",
        "TargetObject"
    )

    # ========================================================
    # HASHES
    # ========================================================

    hashes = get_value(
        data,
        "Hashes"
    )

    # ========================================================
    # PROCESS ACCESS FIELDS - EVENT ID 10
    # ========================================================
    #
    # Sysmon Event ID 10 uses different field names from
    # Event ID 1 and Event ID 3.
    #
    # Example:
    #
    # SourceProcessGUID
    # SourceProcessId
    # SourceImage
    # SourceUser
    # TargetProcessGUID
    # TargetProcessId
    # TargetImage
    # TargetUser
    # GrantedAccess
    # CallTrace
    #
    # These fields are important for detecting suspicious
    # access to sensitive processes such as lsass.exe.
    # ========================================================

    source_process_guid = get_value(
        data,
        "SourceProcessGUID"
    )

    source_process_id = convert_integer(
        get_value(
            data,
            "SourceProcessId"
        )
    )

    source_image = get_value(
        data,
        "SourceImage"
    )

    source_user_name = get_value(
        data,
        "SourceUser"
    )

    target_process_guid = get_value(
        data,
        "TargetProcessGUID"
    )

    target_process_id = convert_integer(
        get_value(
            data,
            "TargetProcessId"
        )
    )

    target_image = get_value(
        data,
        "TargetImage"
    )

    target_user_name = get_value(
        data,
        "TargetUser"
    )

    granted_access = get_value(
        data,
        "GrantedAccess"
    )

    call_trace = get_value(
        data,
        "CallTrace"
    )

    # ========================================================
    # RETURN NORMALIZED EVENT
    # ========================================================

    return {
        "event_id": event_id,
        "event_time": event_time,
        "computer_name": computer_name,
        "user_name": user_name,
        "process_guid": process_guid,
        "process_id": process_id,
        "image": image,
        "command_line": command_line,
        "parent_image": parent_image,
        "parent_command_line": parent_command_line,

        "source_ip": source_ip,
        "source_port": source_port,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "protocol": protocol,

        "dns_query": dns_query,
        "dns_query_status": dns_query_status,

        "target_object": target_object,

        "hashes": hashes,

        # ----------------------------------------------------
        # Event ID 10 fields
        # ----------------------------------------------------

        "source_process_guid": source_process_guid,
        "source_process_id": source_process_id,
        "source_image": source_image,
        "source_user_name": source_user_name,

        "target_process_guid": target_process_guid,
        "target_process_id": target_process_id,
        "target_image": target_image,
        "target_user_name": target_user_name,

        "granted_access": granted_access,
        "call_trace": call_trace,

        "raw_message": xml
    }


# ============================================================
# DATABASE INSERT
# ============================================================

def insert_event(cursor, event):

    query = """
        INSERT INTO sysmon_events (
            event_id,
            event_time,
            computer_name,
            user_name,
            process_guid,
            process_id,
            image,
            command_line,
            parent_image,
            parent_command_line,

            source_ip,
            source_port,
            destination_ip,
            destination_port,
            protocol,

            dns_query,
            dns_query_status,

            target_object,

            hashes,

            source_process_guid,
            source_process_id,
            source_image,
            source_user_name,

            target_process_guid,
            target_process_id,
            target_image,
            target_user_name,

            granted_access,
            call_trace,

            raw_message
        )
        VALUES (
            %(event_id)s,
            %(event_time)s,
            %(computer_name)s,
            %(user_name)s,
            %(process_guid)s,
            %(process_id)s,
            %(image)s,
            %(command_line)s,
            %(parent_image)s,
            %(parent_command_line)s,

            %(source_ip)s,
            %(source_port)s,
            %(destination_ip)s,
            %(destination_port)s,
            %(protocol)s,

            %(dns_query)s,
            %(dns_query_status)s,

            %(target_object)s,

            %(hashes)s,

            %(source_process_guid)s,
            %(source_process_id)s,
            %(source_image)s,
            %(source_user_name)s,

            %(target_process_guid)s,
            %(target_process_id)s,
            %(target_image)s,
            %(target_user_name)s,

            %(granted_access)s,
            %(call_trace)s,

            %(raw_message)s
        )
    """

    cursor.execute(
        query,
        event
    )


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 60)
    print("PROJECT 2: WINDOWS DETECTION PLATFORM")
    print("EVTX -> PostgreSQL Event Parser")
    print("EVENT ID 10 PROCESS ACCESS SUPPORT")
    print("=" * 60)

    # ========================================================
    # CHECK EVTX FILE
    # ========================================================

    if not os.path.exists(INPUT_FILE):

        print(
            f"[!] EVTX file not found: {INPUT_FILE}"
        )

        return

    file_size = os.path.getsize(
        INPUT_FILE
    )

    print(
        f"[+] Input file: {INPUT_FILE}"
    )

    print(
        f"[+] File size: "
        f"{file_size / (1024 * 1024):.2f} MB"
    )

    # ========================================================
    # CONNECT TO POSTGRESQL
    # ========================================================

    print(
        "[+] Connecting to PostgreSQL..."
    )

    try:

        connection = psycopg2.connect(
            **DATABASE
        )

        cursor = connection.cursor()

        print(
            "[+] PostgreSQL connection successful."
        )

    except Exception as error:

        print(
            f"[!] Database connection failed: {error}"
        )

        return

    # ========================================================
    # PROCESS EVTX
    # ========================================================

    processed = 0
    inserted = 0
    skipped = 0
    failed = 0

    event_counts = {}

    print(
        "[+] Reading EVTX records..."
    )

    try:

        with Evtx(INPUT_FILE) as log:

            for record in log.records():

                processed += 1

                try:

                    xml = record.xml()

                    parsed = parse_event(
                        xml
                    )

                    if parsed is None:

                        skipped += 1

                        continue

                    event_id = parsed[
                        "event_id"
                    ]

                    if event_id is None:

                        skipped += 1

                        continue

                    insert_event(
                        cursor,
                        parsed
                    )

                    inserted += 1

                    event_counts[event_id] = (
                        event_counts.get(
                            event_id,
                            0
                        ) + 1
                    )

                    # ------------------------------------------------
                    # Commit every 500 inserted events.
                    # ------------------------------------------------

                    if inserted % 500 == 0:

                        connection.commit()

                        print(
                            f"[+] Processed: "
                            f"{processed} | "
                            f"Inserted: "
                            f"{inserted}"
                        )

                except Exception as error:

                    failed += 1

                    print(
                        f"[!] Failed record "
                        f"{processed}: {error}"
                    )

        connection.commit()

    except Exception as error:

        connection.rollback()

        print(
            f"[!] EVTX processing failed: {error}"
        )

        cursor.close()
        connection.close()

        return

    # ========================================================
    # CLOSE DATABASE
    # ========================================================

    cursor.close()

    connection.close()

    # ========================================================
    # FINAL REPORT
    # ========================================================

    print()

    print("=" * 60)
    print("EVENT PARSING COMPLETE")
    print("=" * 60)

    print(
        f"Records processed : {processed}"
    )

    print(
        f"Events inserted   : {inserted}"
    )

    print(
        f"Events skipped    : {skipped}"
    )

    print(
        f"Events failed     : {failed}"
    )

    print()

    print(
        "Event distribution:"
    )

    for event_id in sorted(event_counts):

        print(
            f"  Event ID {event_id:<3} "
            f"{event_counts[event_id]}"
        )

    print("=" * 60)


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()
