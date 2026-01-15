#!/usr/bin/env python3
"""
Python Log Analyzer
- Parses plain text or JSON logs
- Detects patterns (error spikes, brute force, 5xx spikes, repeated exceptions)
- Outputs: report.txt, stats.json, timeline.csv

Usage examples:
  python log_analyzer.py --input sample.log --out out/
  python log_analyzer.py --input logs/ --out out/ --since "2025-12-01T00:00:00"
  python log_analyzer.py --input app.jsonl --format json --out out/
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple
from collections import Counter, defaultdict


# ----------------------------
# Data model
# ----------------------------

@dataclass
class Event:
    timestamp: datetime
    level: str
    source: str
    message: str
    raw: str

    # extracted fields (optional)
    user: Optional[str] = None
    ip: Optional[str] = None
    request_id: Optional[str] = None
    status_code: Optional[int] = None
    endpoint: Optional[str] = None
    duration_ms: Optional[int] = None
    exception_sig: Optional[str] = None

    def to_row(self) -> Dict[str, Any]:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        return d


# ----------------------------
# Parsing helpers
# ----------------------------

ISO_HINT = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")
PLAIN_LOG_RE = re.compile(
    # Example: 2025-12-20T14:22:10Z INFO auth Login failed user=zain ip=1.2.3.4 request_id=abc123 status=401 path=/login dur_ms=120
    r"""
    ^(?P<ts>\S+)\s+
    (?P<level>[A-Z]+)\s+
    (?P<source>[A-Za-z0-9_.-]+)\s+
    (?P<msg>.*)$
    """,
    re.VERBOSE,
)

KV_RE = re.compile(r"(\b[a-zA-Z_][a-zA-Z0-9_]*\b)=(\".*?\"|\S+)")


def parse_timestamp(ts: str) -> Optional[datetime]:
    """
    Supports:
      - 2025-12-20T14:22:10Z
      - 2025-12-20T14:22:10+00:00
      - 2025-12-20 14:22:10
    """
    try:
        if ts.endswith("Z"):
            return datetime.fromisoformat(ts[:-1]).replace(tzinfo=timezone.utc)
        if "T" in ts:
            # fromisoformat handles offsets like +00:00
            dt = datetime.fromisoformat(ts)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        # fallback: space format
        dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def extract_fields_from_message(msg: str) -> Dict[str, Any]:
    """
    Pull out common fields like user, ip, request_id, status, path, duration.
    """
    out: Dict[str, Any] = {}

    # Key=Value pairs
    for k, v in KV_RE.findall(msg):
        v = v.strip('"')
        out[k.lower()] = v

    # IP heuristic (if not already)
    if "ip" not in out:
        ipm = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", msg)
        if ipm:
            out["ip"] = ipm.group(0)

    # Request ID heuristic
    if "request_id" not in out:
        ridm = re.search(r"\brequest[_-]?id[:=]\s*([A-Za-z0-9_-]+)\b", msg, re.IGNORECASE)
        if ridm:
            out["request_id"] = ridm.group(1)

    # HTTP status code heuristic
    if "status" not in out:
        sm = re.search(r"\bstatus[:=]\s*(\d{3})\b", msg, re.IGNORECASE)
        if sm:
            out["status"] = sm.group(1)

    # Endpoint/path heuristic
    if "path" not in out and "endpoint" not in out:
        pm = re.search(r"\b(path|endpoint)[:=]\s*(/\S+)\b", msg, re.IGNORECASE)
        if pm:
            out[pm.group(1).lower()] = pm.group(2)

    # Duration heuristic
    if "dur_ms" not in out and "duration_ms" not in out:
        dm = re.search(r"\b(dur_ms|duration_ms)[:=]\s*(\d+)\b", msg, re.IGNORECASE)
        if dm:
            out[dm.group(1).lower()] = dm.group(2)

    return out


def exception_signature(msg: str) -> Optional[str]:
    """
    Produce a simple “signature” to group similar exceptions.
    Examples:
      - "NullPointerException at X"
      - "TimeoutError"
      - "Traceback ..." -> "Traceback"
    """
    # Common exception-ish tokens
    m = re.search(r"\b([A-Za-z_]+(?:Exception|Error))\b", msg)
    if m:
        return m.group(1)

    if "traceback" in msg.lower():
        return "Traceback"

    if "exception" in msg.lower():
        return "Exception"

    return None


def parse_plain_line(line: str) -> Optional[Event]:
    m = PLAIN_LOG_RE.match(line.strip())
    if not m:
        return None

    ts = parse_timestamp(m.group("ts"))
    if not ts:
        return None

    level = m.group("level").upper()
    source = m.group("source")
    msg = m.group("msg").strip()

    fields = extract_fields_from_message(msg)

    status_code = None
    if "status" in fields:
        try:
            status_code = int(str(fields["status"]))
        except Exception:
            status_code = None

    dur = None
    for k in ("dur_ms", "duration_ms"):
        if k in fields:
            try:
                dur = int(str(fields[k]))
            except Exception:
                dur = None

    endpoint = fields.get("path") or fields.get("endpoint")
    user = fields.get("user") or fields.get("username")
    ip = fields.get("ip")
    request_id = fields.get("request_id")

    sig = exception_signature(msg)

    return Event(
        timestamp=ts,
        level=level,
        source=source,
        message=msg,
        raw=line.rstrip("\n"),
        user=user,
        ip=ip,
        request_id=request_id,
        status_code=status_code,
        endpoint=endpoint,
        duration_ms=dur,
        exception_sig=sig,
    )


def parse_json_line(line: str) -> Optional[Event]:
    try:
        obj = json.loads(line)
        if not isinstance(obj, dict):
            return None
    except Exception:
        return None

    # Common JSON log keys (adjustable)
    ts_raw = obj.get("timestamp") or obj.get("time") or obj.get("@timestamp")
    level = (obj.get("level") or obj.get("severity") or "INFO").upper()
    source = obj.get("source") or obj.get("logger") or obj.get("service") or "app"
    msg = obj.get("message") or obj.get("msg") or ""

    if not isinstance(ts_raw, str):
        return None
    ts = parse_timestamp(ts_raw)
    if not ts:
        return None

    # pull optional fields if present
    user = obj.get("user") or obj.get("username")
    ip = obj.get("ip")
    request_id = obj.get("request_id") or obj.get("requestId")
    endpoint = obj.get("path") or obj.get("endpoint")
    status_code = obj.get("status_code") or obj.get("status")
    duration_ms = obj.get("duration_ms") or obj.get("dur_ms")

    try:
        status_code = int(status_code) if status_code is not None else None
    except Exception:
        status_code = None

    try:
        duration_ms = int(duration_ms) if duration_ms is not None else None
    except Exception:
        duration_ms = None

    sig = exception_signature(str(msg))

    return Event(
        timestamp=ts,
        level=str(level),
        source=str(source),
        message=str(msg),
        raw=line.rstrip("\n"),
        user=str(user) if user is not None else None,
        ip=str(ip) if ip is not None else None,
        request_id=str(request_id) if request_id is not None else None,
        status_code=status_code,
        endpoint=str(endpoint) if endpoint is not None else None,
        duration_ms=duration_ms,
        exception_sig=sig,
    )


def detect_format_from_sample(lines: List[str]) -> str:
    """
    Returns: "json" or "plain"
    """
    json_hits = 0
    plain_hits = 0
    for line in lines:
        if not line.strip():
            continue
        if parse_json_line(line) is not None:
            json_hits += 1
        if parse_plain_line(line) is not None:
            plain_hits += 1

    # If mostly JSON, use json
    if json_hits > plain_hits:
        return "json"
    return "plain"


def iter_input_lines(path: str) -> Iterable[Tuple[str, str]]:
    """
    Yields (filename, line) for a single file or a directory of files.
    """
    if os.path.isdir(path):
        for root, _, files in os.walk(path):
            for fn in sorted(files):
                full = os.path.join(root, fn)
                if os.path.isfile(full):
                    with open(full, "r", encoding="utf-8", errors="replace") as f:
                        for line in f:
                            yield (full, line)
    else:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                yield (path, line)


# ----------------------------
# Detection logic
# ----------------------------

@dataclass
class Finding:
    type: str
    severity: str
    summary: str
    evidence: Dict[str, Any]


def sliding_window_counts(times: List[datetime], window: timedelta) -> int:
    """
    Returns maximum count of events in any window.
    """
    if not times:
        return 0
    times = sorted(times)
    j = 0
    best = 0
    for i in range(len(times)):
        while times[i] - times[j] > window:
            j += 1
        best = max(best, i - j + 1)
    return best


def detect_bruteforce(events: List[Event], window_minutes: int, threshold: int) -> Optional[Finding]:
    """
    Detect many login failures from same IP or user in a short window.
    Trigger on messages containing "login failed" or "failed login" or auth status 401/403.
    """
    window = timedelta(minutes=window_minutes)

    # Filter auth-like failures
    candidates: List[Event] = []
    for e in events:
        msg = e.message.lower()
        if "login failed" in msg or "failed login" in msg or "authentication failed" in msg:
            candidates.append(e)
            continue
        if e.status_code in (401, 403) and ("/login" in (e.endpoint or "") or "auth" in e.source.lower() or "auth" in msg):
            candidates.append(e)

    if not candidates:
        return None

    by_ip: Dict[str, List[datetime]] = defaultdict(list)
    by_user: Dict[str, List[datetime]] = defaultdict(list)

    for e in candidates:
        if e.ip:
            by_ip[e.ip].append(e.timestamp)
        if e.user:
            by_user[e.user].append(e.timestamp)

    # Find best offender
    best_ip, best_ip_max = None, 0
    for ip, tslist in by_ip.items():
        m = sliding_window_counts(tslist, window)
        if m > best_ip_max:
            best_ip, best_ip_max = ip, m

    best_user, best_user_max = None, 0
    for user, tslist in by_user.items():
        m = sliding_window_counts(tslist, window)
        if m > best_user_max:
            best_user, best_user_max = user, m

    if best_ip_max >= threshold or best_user_max >= threshold:
        who = f"ip={best_ip}" if best_ip_max >= best_user_max else f"user={best_user}"
        count = max(best_ip_max, best_user_max)
        return Finding(
            type="AUTH_BRUTE_FORCE_SUSPECTED",
            severity="HIGH" if count >= threshold * 2 else "MEDIUM",
            summary=f"Possible brute force: {count} auth failures within {window_minutes} minutes for {who}.",
            evidence={
                "window_minutes": window_minutes,
                "threshold": threshold,
                "max_failures_in_window": count,
                "top_ip": best_ip,
                "top_user": best_user,
            },
        )
    return None


def detect_error_spike(events: List[Event], window_minutes: int, threshold: int) -> Optional[Finding]:
    window = timedelta(minutes=window_minutes)

    error_events = [
        e for e in events
        if e.level in ("ERROR", "FATAL") or "exception" in e.message.lower() or "traceback" in e.message.lower()
    ]
    times = [e.timestamp for e in error_events]
    mx = sliding_window_counts(times, window)
    if mx >= threshold:
        return Finding(
            type="ERROR_SPIKE",
            severity="HIGH" if mx >= threshold * 2 else "MEDIUM",
            summary=f"Error spike detected: up to {mx} error/exception events within {window_minutes} minutes.",
            evidence={"window_minutes": window_minutes, "threshold": threshold, "max_in_window": mx},
        )
    return None


def detect_5xx_spike(events: List[Event], window_minutes: int, threshold: int) -> Optional[Finding]:
    window = timedelta(minutes=window_minutes)

    http_5xx = [e for e in events if e.status_code is not None and 500 <= e.status_code <= 599]
    times = [e.timestamp for e in http_5xx]
    mx = sliding_window_counts(times, window)
    if mx >= threshold:
        return Finding(
            type="HTTP_5XX_SPIKE",
            severity="HIGH" if mx >= threshold * 2 else "MEDIUM",
            summary=f"HTTP 5xx spike: up to {mx} responses (5xx) within {window_minutes} minutes.",
            evidence={"window_minutes": window_minutes, "threshold": threshold, "max_in_window": mx},
        )
    return None


def detect_repeated_exceptions(events: List[Event], threshold: int) -> Optional[Finding]:
    sigs = [e.exception_sig for e in events if e.exception_sig]
    if not sigs:
        return None
    c = Counter(sigs)
    top_sig, top_count = c.most_common(1)[0]
    if top_count >= threshold:
        return Finding(
            type="REPEATED_EXCEPTION_SIGNATURE",
            severity="MEDIUM" if top_count < threshold * 2 else "HIGH",
            summary=f"Repeated exception signature: '{top_sig}' occurred {top_count} times.",
            evidence={"signature": top_sig, "count": top_count, "top_5": c.most_common(5)},
        )
    return None


def suspected_root_cause(findings: List[Finding], stats: Dict[str, Any]) -> str:
    """
    Simple rule-based best guess.
    """
    types = {f.type for f in findings}

    if "AUTH_BRUTE_FORCE_SUSPECTED" in types:
        top_ip = None
        for f in findings:
            if f.type == "AUTH_BRUTE_FORCE_SUSPECTED":
                top_ip = f.evidence.get("top_ip")
        return f"Likely security event: suspected brute force against authentication (top_ip={top_ip})."

    if "HTTP_5XX_SPIKE" in types and "ERROR_SPIKE" in types:
        top_err = (stats.get("top_error_messages") or ["unknown"])[0]
        return f"Service instability: 5xx spike aligns with application errors; investigate '{top_err}'."

    if "REPEATED_EXCEPTION_SIGNATURE" in types:
        sig = None
        for f in findings:
            if f.type == "REPEATED_EXCEPTION_SIGNATURE":
                sig = f.evidence.get("signature")
        return f"Probable code/runtime issue: repeated '{sig}' suggests a recurring fault path."

    if "ERROR_SPIKE" in types:
        return "Probable incident: sudden increase in errors/exceptions; review timeline around first spike."

    return "No strong root-cause signal found; review top warnings/errors and context around anomalies."


# ----------------------------
# Reporting
# ----------------------------

def compute_stats(events: List[Event]) -> Dict[str, Any]:
    levels = Counter(e.level for e in events)
    sources = Counter(e.source for e in events)
    ips = Counter(e.ip for e in events if e.ip)
    users = Counter(e.user for e in events if e.user)
    endpoints = Counter(e.endpoint for e in events if e.endpoint)

    # "Top error messages"
    err_msgs = []
    for e in events:
        if e.level in ("ERROR", "FATAL") or "exception" in e.message.lower() or "traceback" in e.message.lower():
            err_msgs.append(clean_message(e.message))
    top_err = [m for m, _ in Counter(err_msgs).most_common(5)]

    # time range
    if events:
        start = min(e.timestamp for e in events)
        end = max(e.timestamp for e in events)
    else:
        start = end = None

    return {
        "total_events": len(events),
        "time_range": {
            "start": start.isoformat() if start else None,
            "end": end.isoformat() if end else None,
        },
        "levels": dict(levels),
        "top_sources": sources.most_common(5),
        "top_ips": ips.most_common(5),
        "top_users": users.most_common(5),
        "top_endpoints": endpoints.most_common(5),
        "top_error_messages": top_err,
    }


def clean_message(msg: str) -> str:
    """
    Normalize message for grouping:
    - remove long ids/numbers
    """
    msg = re.sub(r"\b[0-9a-f]{8,}\b", "<id>", msg, flags=re.IGNORECASE)
    msg = re.sub(r"\b\d+\b", "<n>", msg)
    msg = re.sub(r"\s+", " ", msg).strip()
    return msg[:240]


def build_timeline(events: List[Event], max_lines: int = 60) -> List[str]:
    """
    A human-readable “incident story”.
    """
    if not events:
        return ["(no events)"]

    events_sorted = sorted(events, key=lambda e: e.timestamp)

    # Highlighted events
    highlights: List[Event] = []
    for e in events_sorted:
        msg_l = e.message.lower()
        if e.level in ("ERROR", "FATAL"):
            highlights.append(e)
        elif "login failed" in msg_l or "failed login" in msg_l:
            highlights.append(e)
        elif e.status_code is not None and 500 <= e.status_code <= 599:
            highlights.append(e)
        elif "deploy" in msg_l or "release" in msg_l or "restart" in msg_l:
            highlights.append(e)

    if not highlights:
        # fallback: take evenly spaced sample
        step = max(1, len(events_sorted) // max_lines)
        highlights = events_sorted[::step][:max_lines]

    lines = []
    for e in highlights[:max_lines]:
        parts = [e.timestamp.isoformat(), e.level, e.source, "-", e.message]
        if e.ip:
            parts.append(f"(ip={e.ip})")
        if e.user:
            parts.append(f"(user={e.user})")
        if e.status_code:
            parts.append(f"(status={e.status_code})")
        if e.endpoint:
            parts.append(f"(path={e.endpoint})")
        lines.append(" ".join(parts))
    return lines


def write_outputs(out_dir: str, events: List[Event], findings: List[Finding], stats: Dict[str, Any]) -> Tuple[str, str, str]:
    os.makedirs(out_dir, exist_ok=True)

    # timeline.csv
    csv_path = os.path.join(out_dir, "timeline.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=list(Event.__dataclass_fields__.keys()),
        )
        writer.writeheader()
        for e in sorted(events, key=lambda x: x.timestamp):
            writer.writerow(e.to_row())

    # stats.json
    json_path = os.path.join(out_dir, "stats.json")
    payload = {
        "stats": stats,
        "findings": [asdict(f) for f in findings],
        "root_cause": suspected_root_cause(findings, stats),
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    # report.txt
    report_path = os.path.join(out_dir, "report.txt")
    timeline_lines = build_timeline(events)
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("PYTHON LOG ANALYZER REPORT\n")
        f.write("=" * 28 + "\n\n")

        f.write("SUMMARY STATS\n")
        f.write("-" * 12 + "\n")
        f.write(f"Total events: {stats.get('total_events')}\n")
        tr = stats.get("time_range", {})
        f.write(f"Time range: {tr.get('start')}  ->  {tr.get('end')}\n")
        f.write(f"Levels: {stats.get('levels')}\n\n")

        f.write("TOP SIGNALS\n")
        f.write("-" * 11 + "\n")
        f.write(f"Top sources: {stats.get('top_sources')}\n")
        f.write(f"Top IPs: {stats.get('top_ips')}\n")
        f.write(f"Top users: {stats.get('top_users')}\n")
        f.write(f"Top endpoints: {stats.get('top_endpoints')}\n")
        f.write(f"Top error messages: {stats.get('top_error_messages')}\n\n")

        f.write("DETECTIONS / FINDINGS\n")
        f.write("-" * 20 + "\n")
        if findings:
            for i, fd in enumerate(findings, 1):
                f.write(f"{i}. [{fd.severity}] {fd.type}: {fd.summary}\n")
                f.write(f"   Evidence: {json.dumps(fd.evidence, ensure_ascii=False)}\n")
        else:
            f.write("No major incidents detected by current rules.\n")
        f.write("\n")

        f.write("SUSPECTED ROOT CAUSE (BEST GUESS)\n")
        f.write("-" * 33 + "\n")
        f.write(suspected_root_cause(findings, stats) + "\n\n")

        f.write("INCIDENT TIMELINE (HIGHLIGHTS)\n")
        f.write("-" * 29 + "\n")
        for line in timeline_lines:
            f.write(line + "\n")

    return report_path, json_path, csv_path


# ----------------------------
# Main
# ----------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Python Log Analyzer")
    p.add_argument("--input", required=True, help="Path to log file OR directory containing logs")
    p.add_argument("--out", default="out", help="Output directory (default: out/)")
    p.add_argument("--format", choices=["auto", "plain", "json"], default="auto", help="Log format (default: auto)")

    p.add_argument("--since", default=None, help='Only include events at/after this timestamp (e.g. "2025-12-01T00:00:00")')
    p.add_argument("--until", default=None, help='Only include events before/at this timestamp (e.g. "2025-12-02T00:00:00")')

    # Detection tuning
    p.add_argument("--window-min", type=int, default=5, help="Window size minutes for spike detection (default: 5)")
    p.add_argument("--err-threshold", type=int, default=20, help="Error spike threshold (default: 20)")
    p.add_argument("--auth-threshold", type=int, default=10, help="Auth failure threshold (default: 10)")
    p.add_argument("--http5xx-threshold", type=int, default=15, help="HTTP 5xx spike threshold (default: 15)")
    p.add_argument("--repeat-ex-threshold", type=int, default=10, help="Repeated exception signature threshold (default: 10)")

    return p.parse_args()


def parse_bound(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    dt = parse_timestamp(ts)
    if dt:
        return dt
    # try common fallback
    try:
        return datetime.fromisoformat(ts).replace(tzinfo=timezone.utc)
    except Exception:
        return None


def main() -> int:
    args = parse_args()

    since = parse_bound(args.since)
    until = parse_bound(args.until)

    # peek first non-empty lines to detect format if auto
    sample = []
    for _, line in iter_input_lines(args.input):
        if line.strip():
            sample.append(line)
        if len(sample) >= 30:
            break

    if args.format == "auto":
        fmt = detect_format_from_sample(sample) if sample else "plain"
    else:
        fmt = args.format

    parser_fn = parse_json_line if fmt == "json" else parse_plain_line

    events: List[Event] = []
    for filename, line in iter_input_lines(args.input):
        e = parser_fn(line)
        if not e:
            continue
        # add source file name into source if you want (optional)
        # e.source = f"{e.source}@{os.path.basename(filename)}"

        if since and e.timestamp < since:
            continue
        if until and e.timestamp > until:
            continue
        events.append(e)

    events.sort(key=lambda e: e.timestamp)

    stats = compute_stats(events)

    findings: List[Finding] = []
    bf = detect_bruteforce(events, window_minutes=args.window_min, threshold=args.auth_threshold)
    if bf: findings.append(bf)

    es = detect_error_spike(events, window_minutes=args.window_min, threshold=args.err_threshold)
    if es: findings.append(es)

    hs = detect_5xx_spike(events, window_minutes=args.window_min, threshold=args.http5xx_threshold)
    if hs: findings.append(hs)

    rx = detect_repeated_exceptions(events, threshold=args.repeat_ex_threshold)
    if rx: findings.append(rx)

    report_path, json_path, csv_path = write_outputs(args.out, events, findings, stats)

    # console summary
    print(f"Format: {fmt}")
    print(f"Parsed events: {len(events)}")
    print(f"Findings: {len(findings)}")
    print(f"Report:  {report_path}")
    print(f"Stats:   {json_path}")
    print(f"Timeline:{csv_path}")

    # exit code: 1 if incident detected
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
