#!/usr/bin/env python3
"""Write the is-a.dev registration files for SentinelEdge's domain (ADR-0025).

    terraform -chdir=terraform/environments/dev output -json certificate_validation_records \
      | scripts/isadev-records.py <your is-a-dev/register fork>/domains

Reads the dev stack's certificate validation records (JSON on stdin) and writes:

- sentineledge.json: the parent name. Its CAA records allow only Amazon to issue certificates
  for it and every name under it, and forbid wildcard certificates.
- _<token>.app.sentineledge.json: the ACM validation CNAME. It never changes for this account
  and name, so it is published once.

The CloudFront record (app.sentineledge.json) is added in Phase 5, when the distribution exists.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PARENT = "sentineledge"
SUFFIX = ".is-a.dev"
PROJECT_URL = "https://github.com/Bionic-Hacker/Sentinel-Edge"


def validation_records() -> list[dict[str, str]]:
    try:
        records = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        sys.exit(f"isadev-records: stdin is not the JSON from terraform output -json ({exc})")
    if not isinstance(records, list) or not records:
        sys.exit("isadev-records: the dev stack has no certificate validation records yet")
    return records


def label_for(fqdn: str) -> str:
    """'_abc.app.sentineledge.is-a.dev.' -> '_abc.app.sentineledge'."""
    name = fqdn.rstrip(".").lower()
    if not name.endswith(f".{PARENT}{SUFFIX}"):
        sys.exit(f"isadev-records: {fqdn} is not under {PARENT}{SUFFIX}")
    return name[: -len(SUFFIX)]


def write(path: Path, doc: dict[str, object]) -> None:
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {path}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("domains_dir", type=Path, help="domains/ folder of your register fork")
    parser.add_argument("--username", default="Bionic-Hacker", help="GitHub user owning the names")
    args = parser.parse_args()

    if not args.domains_dir.is_dir():
        sys.exit(f"isadev-records: {args.domains_dir} is not a directory")
    owner = {"username": args.username}
    records = validation_records()  # read and checked before anything is written

    write(
        args.domains_dir / f"{PARENT}.json",
        {
            "owner": owner,
            "records": {
                "CAA": [
                    {"flags": 0, "tag": "issue", "value": "amazon.com"},
                    {"flags": 0, "tag": "issuewild", "value": ";"},
                ],
                "TXT": f"SentinelEdge, an application and API security platform: {PROJECT_URL}",
            },
        },
    )

    for record in records:
        if record.get("type") != "CNAME":
            sys.exit(f"isadev-records: unexpected record type {record.get('type')}")
        write(
            args.domains_dir / f"{label_for(record['name'])}.json",
            {"owner": owner, "records": {"CNAME": record["value"].rstrip(".")}},
        )


if __name__ == "__main__":
    main()
