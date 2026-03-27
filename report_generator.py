#!/usr/bin/env python3
import json
import os
import pickle
import sqlite3
import urllib.parse
import urllib.request


DB_PATH = os.path.expanduser("~/legacy_log_processor_test_env/logs.db")
REPORT_PATH = os.path.expanduser("~/legacy_log_processor_test_env/report.html")
GEO_API_BASE = "http://localhost:8080/geo"


def get_geo(ip_address: str) -> dict:
    url = f"{GEO_API_BASE}?{urllib.parse.urlencode({'ip': ip_address})}"
    with urllib.request.urlopen(url, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def extract_user_id(metadata_blob: bytes):
    # Required by legacy system constraints: metadata is a pickled Python object.
    metadata = pickle.loads(metadata_blob)
    if isinstance(metadata, dict):
        return metadata.get("user_id")
    return getattr(metadata, "user_id", None)


def load_failed_attempts() -> list[dict]:
    conn = sqlite3.connect(DB_PATH)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT username, ip_address, metadata
            FROM login_logs
            WHERE status = 'FAILED'
            ORDER BY id
            """
        )

        rows = []
        for username, ip_address, metadata_blob in cursor.fetchall():
            user_id = extract_user_id(metadata_blob)
            geo = get_geo(ip_address)
            rows.append(
                {
                    "username": username,
                    "user_id": user_id,
                    "ip_address": ip_address,
                    "country": geo.get("country", "Unknown"),
                    "flag_html": geo.get("flag_html", ""),
                }
            )
        return rows
    finally:
        conn.close()


def render_report(rows: list[dict]) -> str:
    table_rows = []
    for row in rows:
        table_rows.append(
            (
                "<tr>"
                f"<td>{row['username']}</td>"
                f"<td>{row['user_id']}</td>"
                f"<td>{row['ip_address']}</td>"
                f"<td>{row['country']}</td>"
                f"<td>{row['flag_html']}</td>"
                "</tr>"
            )
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Failed Login Attempts Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
    th {{ background: #f4f4f4; }}
  </style>
</head>
<body>
  <h1>Failed Login Attempts</h1>
  <table>
    <thead>
      <tr>
        <th>Username</th>
        <th>User ID</th>
        <th>IP Address</th>
        <th>Country</th>
        <th>Flag</th>
      </tr>
    </thead>
    <tbody>
      {''.join(table_rows)}
    </tbody>
  </table>
</body>
</html>
"""


def main() -> None:
    rows = load_failed_attempts()
    os.makedirs(os.path.dirname(REPORT_PATH), exist_ok=True)
    html = render_report(rows)
    with open(REPORT_PATH, "w", encoding="utf-8") as report_file:
        report_file.write(html)
    print(f"Generated report: {REPORT_PATH}")
    print(f"Failed attempts included: {len(rows)}")


if __name__ == "__main__":
    main()
