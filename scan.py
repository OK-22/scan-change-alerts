#!/usr/bin/env python3
"""
Scan targets with nmap, compare the open ports with a saved baseline, and write a
markdown report. Designed to run on a schedule (see .github/workflows/scan.yml).

Only scan systems you own or have written permission to scan.

Examples:
  python scan.py --targets targets.txt --baseline baseline.json
  python scan.py --targets targets.txt --baseline baseline.json --update-baseline
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone


def read_targets(path):
    with open(path, encoding="utf-8") as f:
        lines = [line.strip() for line in f]
    return [t for t in lines if t and not t.startswith("#")]


def run_nmap(targets, ports):
    if shutil.which("nmap") is None:
        sys.exit("nmap was not found. Install it first (https://nmap.org/download).")
    cmd = ["nmap", "-sT", "-Pn", "-T3", "-p", ports, "-oX", "-"] + targets
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        sys.exit(f"nmap failed (exit {proc.returncode}): {proc.stderr.strip()}")
    return proc.stdout


def parse_nmap_xml(xml_text):
    """Return {host: {"80/tcp": "http", ...}} for hosts that are up."""
    root = ET.fromstring(xml_text)
    result = {}
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        addr = host.find("address")
        if addr is None:
            continue
        ports = {}
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            name = service.get("name") if service is not None else "unknown"
            ports[f"{port.get('portid')}/{port.get('protocol')}"] = name
        result[addr.get("addr")] = ports
    return result


def compare(baseline, current):
    """Describe what changed. Only new hosts or new open ports raise an alert."""
    new_hosts = sorted(h for h in current if h not in baseline)
    gone_hosts = sorted(h for h in baseline if h not in current)
    new_ports, closed_ports = {}, {}
    for host, ports in current.items():
        old = baseline.get(host, {})
        added = {p: s for p, s in ports.items() if p not in old}
        if added:
            new_ports[host] = added
        removed = {p: s for p, s in old.items() if p not in ports}
        if removed and host in baseline:
            closed_ports[host] = removed
    return {
        "new_hosts": new_hosts,
        "gone_hosts": gone_hosts,
        "new_ports": new_ports,
        "closed_ports": closed_ports,
        "alert": bool(new_ports),
        "changed": bool(new_hosts or gone_hosts or new_ports or closed_ports),
    }


def render_report(diff, targets, when):
    lines = ["# Port scan report", "", f"Scanned at {when} UTC. Targets: {', '.join(targets)}", ""]
    if diff["new_ports"]:
        lines += ["## New open ports", "", "| Host | Port | Service |", "|---|---|---|"]
        for host, ports in sorted(diff["new_ports"].items()):
            for port, service in sorted(ports.items()):
                lines.append(f"| {host} | {port} | {service} |")
        lines.append("")
    if diff["new_hosts"]:
        lines += ["## New hosts", ""] + [f"- {h}" for h in diff["new_hosts"]] + [""]
    if diff["closed_ports"]:
        lines += ["## Ports no longer open", "", "| Host | Port | Service |", "|---|---|---|"]
        for host, ports in sorted(diff["closed_ports"].items()):
            for port, service in sorted(ports.items()):
                lines.append(f"| {host} | {port} | {service} |")
        lines.append("")
    if diff["gone_hosts"]:
        lines += ["## Hosts no longer seen", ""] + [f"- {h}" for h in diff["gone_hosts"]] + [""]
    if not diff["changed"]:
        lines += ["No changes since the baseline.", ""]
    return "\n".join(lines)


def set_output(name, value):
    path = os.environ.get("GITHUB_OUTPUT")
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"{name}={value}\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--targets", default="targets.txt")
    ap.add_argument("--ports", default="1-1024,8000-8100")
    ap.add_argument("--baseline", default="baseline.json")
    ap.add_argument("--latest", default="results/latest.json")
    ap.add_argument("--report", default="results/report.md")
    ap.add_argument("--update-baseline", action="store_true", help="overwrite the baseline with this scan")
    args = ap.parse_args()

    targets = read_targets(args.targets)
    if not targets:
        sys.exit("No targets found in " + args.targets)
    current = parse_nmap_xml(run_nmap(targets, args.ports))

    os.makedirs(os.path.dirname(args.latest) or ".", exist_ok=True)
    with open(args.latest, "w", encoding="utf-8") as f:
        json.dump(current, f, indent=2, sort_keys=True)

    when = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
    if not os.path.exists(args.baseline):
        with open(args.baseline, "w", encoding="utf-8") as f:
            json.dump(current, f, indent=2, sort_keys=True)
        print(f"No baseline found. Saved the first scan as {args.baseline}; no alert on a first run.")
        set_output("alert", "false")
        return

    with open(args.baseline, encoding="utf-8") as f:
        baseline = json.load(f)
    diff = compare(baseline, current)
    report = render_report(diff, targets, when)
    with open(args.report, "w", encoding="utf-8") as f:
        f.write(report)
    print(report)

    if args.update_baseline and diff["changed"]:
        with open(args.baseline, "w", encoding="utf-8") as f:
            json.dump(current, f, indent=2, sort_keys=True)
        print(f"Baseline updated: {args.baseline}")
    set_output("alert", "true" if diff["alert"] else "false")


if __name__ == "__main__":
    main()
