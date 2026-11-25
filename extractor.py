#!/usr/bin/env python3
"""
Query a SIEM (v2 events API) for events and save the response to events.json.

Example:
    ./siem_query.py \
        --url https://siem-en.city12.stf \
        --token "$SIEM_TOKEN" \
        --time-from "22.11.2026 08:00:00" \
        --time-to   "22.11.2026 10:00:00" \
        --filter 'object = "process"'
"""

import argparse
import json
import sys
from datetime import datetime
from urllib.parse import urlencode

try:
    from zoneinfo import ZoneInfo          # Python 3.9+
except ImportError:                        # pragma: no cover
    ZoneInfo = None

import requests

TIME_FORMAT = "%d.%m.%Y %H:%M:%S"
OUTPUT_FILE = "events.json"
DEFAULT_LIMIT = 50000

DEFAULT_SELECT = [
    "time",
    "event_src.host",
    "text",
    "id",
    "object.type",
    "object.process.cmdline",
    "object.process.id",
    "object.process.parent.id",
]


def to_unix(value: str, tz_name: str | None) -> int:
    """Parse 'DD.MM.YYYY HH:MM:SS' into Unix epoch seconds."""
    try:
        dt = datetime.strptime(value, TIME_FORMAT)
    except ValueError:
        raise SystemExit(
            f"error: invalid time '{value}', expected format 'DD.MM.YYYY HH:MM:SS'"
        )

    if tz_name:
        if ZoneInfo is None:
            raise SystemExit("error: --tz requires Python 3.9+")
        try:
            dt = dt.replace(tzinfo=ZoneInfo(tz_name))
        except Exception:
            raise SystemExit(f"error: unknown timezone '{tz_name}'")

    # Naive datetime -> interpreted as local system time
    return int(dt.timestamp())


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        description="Send a POST request to a SIEM /api/events/v2/events endpoint "
                    f"and save the response to {OUTPUT_FILE}.",
    )
    p.add_argument("--url", required=True,
                   help="Base URL, e.g. https://siem-en.city12.stf")
    p.add_argument("--token", required=True,
                   help="Bearer token for the Authorization header")
    p.add_argument("--time-from", required=True, metavar="'DD.MM.YYYY HH:MM:SS'")
    p.add_argument("--time-to",   required=True, metavar="'DD.MM.YYYY HH:MM:SS'")
    p.add_argument("--filter", default='object = "process"',
                   help='Value of the "where" field '
                        '(default: object = "process")')
    p.add_argument("--select", default=None,
                   help="Comma-separated list of fields to select "
                        "(default: built-in set of process fields)")
    p.add_argument("--limit", type=int, default=DEFAULT_LIMIT,
                   help=f"Value of the 'limit' query parameter "
                        f"(default: {DEFAULT_LIMIT})")
    p.add_argument("--tz", default=None,
                   help="IANA timezone for --time-from/--time-to "
                        "(default: local system timezone)")
    p.add_argument("--timeout", type=float, default=60.0,
                   help="HTTP timeout in seconds (default: 60)")
    p.add_argument("-k", "--insecure", action="store_true",
                   help="Do not verify TLS certificate (self-signed SIEM)")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Print the request URL and payload to stderr")
    args = p.parse_args(argv)

    if args.limit < 1:
        p.error("--limit must be a positive integer")

    time_from = to_unix(args.time_from, args.tz)
    time_to   = to_unix(args.time_to,   args.tz)
    if time_from > time_to:
        p.error("--time-from must be <= --time-to")

    select = DEFAULT_SELECT
    if args.select:
        select = [s.strip() for s in args.select.split(",") if s.strip()]

    payload = {
        "filter": {
            "aggregateBy": [],
            "aliases": None,
            "distributeBy": [],
            "groupBy": [],
            "orderBy": [
                {"field": "time", "sortOrder": "descending"}
            ],
            "select": select,
            "top": None,
            "where": args.filter,
        },
        "groupValues": [],
        "timeFrom": time_from,   # Unix epoch seconds
        "timeTo":   time_to,     # Unix epoch seconds
    }

    query = urlencode({"limit": args.limit})
    url = f"{args.url.rstrip('/')}/api/events/v2/events?{query}"

    headers = {
        "Authorization": f"Bearer {args.token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    if args.verbose:
        print(f"POST {url}", file=sys.stderr)
        print(json.dumps(payload, indent=2), file=sys.stderr)

    try:
        resp = requests.post(
            url,
            headers=headers,
            json=payload,
            timeout=args.timeout,
            verify=not args.insecure,
        )
    except requests.RequestException as exc:
        print(f"error: request failed: {exc}", file=sys.stderr)
        return 1

    if not resp.ok:
        print(f"error: HTTP {resp.status_code} {resp.reason}", file=sys.stderr)
        print(resp.text[:2000], file=sys.stderr)
        return 1

    try:
        data = resp.json()
    except ValueError:
        # Not JSON: save raw text so nothing is lost
        with open(OUTPUT_FILE, "w", encoding="utf-8") as fh:
            fh.write(resp.text)
        print(f"Non-JSON response saved to {OUTPUT_FILE}", file=sys.stderr)
        return 0

    with open(OUTPUT_FILE, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)

    print(f"Response saved to {OUTPUT_FILE}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
