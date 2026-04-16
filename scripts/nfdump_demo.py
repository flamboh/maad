#!/usr/bin/env python3
"""Load IPv4 addresses via nfdump, then run MAAD once per address bucket."""

from __future__ import annotations

import argparse
import ipaddress
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

MIN_MAAD_ADDRS = 2
REPO_ROOT = Path(__file__).resolve().parents[1]


@dataclass
class AddressBuckets:
    source: list[ipaddress.IPv4Address]
    destination: list[ipaddress.IPv4Address]

    def as_serializable(self) -> dict[str, list[str]]:
        return {
            "source": [str(addr) for addr in self.source],
            "destination": [str(addr) for addr in self.destination],
        }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Read a NetFlow file with nfdump and run MAAD over the extracted IPv4 addresses.",
    )
    parser.add_argument("flow_file", type=Path, help="Path to an nfdump-readable flow file.")
    parser.add_argument(
        "--maad-bin",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "MAAD",
        help="Path to the MAAD executable. Default: repo-local ./MAAD",
    )
    parser.add_argument(
        "--direction",
        choices=("source", "destination", "both"),
        default="both",
        help="Which address bucket to analyze. Default: both",
    )
    parser.add_argument(
        "--indent",
        type=int,
        default=2,
        help="JSON indent for the demo output. Default: 2",
    )
    parser.add_argument(
        "--show-addresses",
        action="store_true",
        help="Include the full loaded source/destination address lists in the output JSON.",
    )
    return parser.parse_args()


def load_ipv4_buckets(flow_file: Path) -> AddressBuckets:
    result = subprocess.run(
        ["nfdump", "-r", str(flow_file), "-q", "-o", "fmt:%sa,%da", "ipv4"],
        check=True,
        capture_output=True,
        text=True,
    )

    source: set[ipaddress.IPv4Address] = set()
    destination: set[ipaddress.IPv4Address] = set()

    for raw_line in result.stdout.splitlines():
        if not raw_line.strip() or "," not in raw_line:
            continue

        src_raw, dst_raw = raw_line.split(",", 1)

        try:
            source.add(ipaddress.IPv4Address(src_raw.strip()))
        except ipaddress.AddressValueError:
            pass

        try:
            destination.add(ipaddress.IPv4Address(dst_raw.strip()))
        except ipaddress.AddressValueError:
            pass

    return AddressBuckets(
        source=sorted(source),
        destination=sorted(destination),
    )


def resolve_maad_bin(maad_bin: Path) -> Path:
    candidates: list[Path] = []

    if maad_bin.is_absolute():
        candidates.append(maad_bin)
    else:
        candidates.append((Path.cwd() / maad_bin).resolve())
        candidates.append((REPO_ROOT / maad_bin).resolve())

    if maad_bin.name == maad_bin.as_posix():
        candidates.append((REPO_ROOT / maad_bin.name).resolve())

    for candidate in candidates:
        if candidate.is_file():
            return candidate

    return candidates[0] if candidates else maad_bin.resolve()


def run_maad(maad_bin: Path, addresses: list[ipaddress.IPv4Address]) -> dict:
    input_payload = "\n".join(str(addr) for addr in addresses)
    try:
        result = subprocess.run(
            [
                str(maad_bin),
                "--input",
                "-",
                "--output",
                "-",
                "--format",
                "json",
                "--structure",
                "--spectrum",
                "--dimensions",
            ],
            check=True,
            input=input_payload,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(f"Failed to execute MAAD binary: {maad_bin}") from exc
    return json.loads(result.stdout)


def select_buckets(buckets: AddressBuckets, direction: str) -> dict[str, list[ipaddress.IPv4Address]]:
    if direction == "source":
        return {"source": buckets.source}
    if direction == "destination":
        return {"destination": buckets.destination}
    return {
        "source": buckets.source,
        "destination": buckets.destination,
    }


def main() -> int:
    args = parse_args()
    args.maad_bin = resolve_maad_bin(args.maad_bin)

    if not args.flow_file.is_file():
        print(f"Flow file not found: {args.flow_file}", file=sys.stderr)
        return 1

    if not args.maad_bin.is_file():
        print(
            f"MAAD binary not found: {args.maad_bin}\n"
            f"Tip: omit --maad-bin to use the repo-local default at {REPO_ROOT / 'MAAD'}",
            file=sys.stderr,
        )
        return 1

    buckets = load_ipv4_buckets(args.flow_file)
    selected = select_buckets(buckets, args.direction)

    analyses = {}
    for name, addresses in selected.items():
        if len(addresses) < MIN_MAAD_ADDRS:
            analyses[name] = {
                "addressCount": len(addresses),
                "skipped": True,
                "reason": f"MAAD needs at least {MIN_MAAD_ADDRS} unique IPv4 addresses for this demo.",
            }
            continue

        analyses[name] = {
            "addressCount": len(addresses),
            "result": run_maad(args.maad_bin, addresses),
        }

    demo_output = {
        "flowFile": str(args.flow_file),
        "loadedAddressCounts": {
            "source": len(buckets.source),
            "destination": len(buckets.destination),
        },
        "analyses": analyses,
    }
    if args.show_addresses:
        demo_output["loadedAddresses"] = buckets.as_serializable()
    print(json.dumps(demo_output, indent=args.indent))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
