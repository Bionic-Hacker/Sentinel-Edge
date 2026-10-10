#!/usr/bin/env python3
"""Print the DNS records SentinelEdge's zone needs, from the dev stack's outputs (ADR-0025).

    terraform -chdir=terraform/environments/dev output -json certificate_validation_records \\
      | scripts/dns-records.py [--zone sentineledge.dedyn.io]

The zone is hosted by deSEC (desec.io). Records are entered in its web interface as a subname
(the part before the zone, empty for the zone itself), a type and a value:

- CAA at the zone: only Amazon may issue certificates for the zone and every name under it, and
  no one may issue wildcard certificates.
- The ACM validation CNAME. It is the same for every certificate this account requests for the
  name, in any Region, so it is entered once and kept.

The CloudFront record for the platform's name follows in Phase 5, when the distribution exists.
"""

from __future__ import annotations

import argparse
import json
import sys

CAA = ['0 issue "amazon.com"', '0 issuewild ";"']


def validation_records() -> list[dict[str, str]]:
    try:
        records = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        sys.exit(f"dns-records: stdin is not the JSON from terraform output -json ({exc})")
    if not isinstance(records, list) or not records:
        sys.exit("dns-records: the dev stack has no certificate validation records yet")
    return records


def subname(fqdn: str, zone: str) -> str:
    """'_abc.app.sentineledge.dedyn.io.' -> '_abc.app' for zone 'sentineledge.dedyn.io'."""
    name = fqdn.rstrip(".").lower()
    if name == zone:
        return ""
    if not name.endswith(f".{zone}"):
        sys.exit(f"dns-records: {fqdn} is not in the zone {zone}")
    return name[: -len(zone) - 1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--zone", default="sentineledge.dedyn.io", help="the zone at deSEC")
    args = parser.parse_args()
    zone = args.zone.rstrip(".").lower()

    rows = [("(zone itself)", "CAA", value) for value in CAA]
    for record in validation_records():
        if record.get("type") != "CNAME":
            sys.exit(f"dns-records: unexpected record type {record.get('type')}")
        rows.append((subname(record["name"], zone), "CNAME", record["value"].rstrip(".") + "."))

    print(f"Zone: {zone}\n")
    width = max(len(r[0]) for r in rows)
    print(f"{'Subname'.ljust(width)}  Type   Value")
    for name, rtype, value in rows:
        print(f"{name.ljust(width)}  {rtype.ljust(5)}  {value}")


if __name__ == "__main__":
    main()
