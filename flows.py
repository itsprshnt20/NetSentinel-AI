"""Offline parsing, outbound aggregation, and baseline-only anomaly scoring."""
import csv
import io
import ipaddress
import json
import re
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone

import numpy as np
from sklearn.ensemble import IsolationForest

FIELDS = ("timestamp", "source_ip", "destination_ip", "destination_port", "protocol", "bytes", "packets")
FEATURES = ("Bytes", "Packets", "Distinct destinations", "Flow count")
PROTOCOLS = {"TCP", "UDP", "ICMP", "ICMPV6"}
DEFAULT_CIDRS = "10.0.0.0/8"
MAX_BYTES = 3 * 1024 * 1024
MAX_ROWS = 30_000
MAX_COUNTER = 10**12
MIN_BASELINE = 24
MIN_SOURCE = 8
SEED = 42
TREES = 160
CONTAMINATION = 0.05
PERCENTILE = 95
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
TIMESTAMP = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)?"
)


class InputError(ValueError):
    pass


@dataclass(frozen=True)
class Flow:
    row: int
    timestamp: datetime
    source_ip: str
    destination_ip: str
    destination_port: int
    protocol: str
    bytes: int
    packets: int

    def export(self):
        return {**asdict(self), "timestamp": iso(self.timestamp)}


@dataclass(frozen=True)
class Rejected:
    row: int
    reason: str


@dataclass(frozen=True)
class Window:
    source: str
    start: datetime
    flows: tuple[Flow, ...]

    def values(self):
        return (sum(flow.bytes for flow in self.flows), sum(flow.packets for flow in self.flows),
                len({flow.destination_ip for flow in self.flows}), len(self.flows))


@dataclass(frozen=True)
class Reference:
    label: str
    size: int
    medians: tuple
    p95: tuple


@dataclass(frozen=True)
class Finding:
    window: Window
    score: float
    flagged: bool
    reference: Reference


@dataclass(frozen=True)
class Analysis:
    source_label: str
    baseline_size: int
    minutes: int
    cidrs: tuple
    findings: tuple[Finding, ...]
    baseline_ignored: int
    evaluation_ignored: int


def iso(timestamp):
    return timestamp.isoformat().replace("+00:00", "Z")


def parse_timestamp(value):
    if not TIMESTAMP.fullmatch(value):
        raise ValueError("timestamp must be ISO 8601 with seconds and optional UTC offset")
    try:
        timestamp = datetime.fromisoformat(value)
        timestamp = (timestamp if timestamp.tzinfo else timestamp.replace(tzinfo=timezone.utc)).astimezone(
            timezone.utc
        )
        if not 1970 <= timestamp.year <= 2100:
            raise ValueError
        return timestamp
    except (ValueError, OverflowError) as exc:
        raise ValueError("timestamp must be a valid date in UTC years 1970–2100") from exc


def parse_ip(value):
    if "%" in value:
        raise ValueError("IP zone identifiers are unsupported")
    return str(ipaddress.ip_address(value))


def parse_integer(value, maximum):
    if not re.fullmatch(r"[0-9]{1,13}", value) or int(value) > maximum:
        raise ValueError(f"must be an integer from 0 to {maximum:,}")
    return int(value)


def parse_record(row, columns, values):
    data = dict(zip(columns, map(str.strip, values)))
    checked, failures = {}, []
    parsers = {
        "timestamp": parse_timestamp, "source_ip": parse_ip, "destination_ip": parse_ip,
        "destination_port": lambda value: parse_integer(value, 65535),
        "bytes": lambda value: parse_integer(value, MAX_COUNTER),
        "packets": lambda value: parse_integer(value, MAX_COUNTER),
    }
    for name, parser in parsers.items():
        try:
            checked[name] = parser(data[name])
        except ValueError as exc:
            failures.append(f"{name}: {exc}" if name not in {"source_ip", "destination_ip"} else
                            f"{name}: invalid IPv4 or IPv6 address")
    protocol = data["protocol"].upper()
    if protocol not in PROTOCOLS:
        failures.append("protocol: use TCP, UDP, ICMP, or ICMPV6")
    return (None, "; ".join(failures)) if failures else (Flow(row, protocol=protocol, **checked), "")


def parse_csv(raw):
    if len(raw) > MAX_BYTES:
        raise InputError("CSV exceeds 3 MiB. Export a smaller time range.")
    if b"\x00" in raw:
        raise InputError("CSV contains binary data. Export it as UTF-8 text.")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise InputError("CSV must be UTF-8 encoded.") from exc
    reader = csv.reader(io.StringIO(text, newline=""), strict=True)
    try:
        headers = [field.strip().lower() for field in next(reader, [])]
    except csv.Error as exc:
        raise InputError("Malformed CSV header. Re-export the file.") from exc
    if len(headers) != len(FIELDS) or set(headers) != set(FIELDS):
        raise InputError("CSV must contain exactly these unique columns: " + ", ".join(FIELDS) + ".")
    valid, rejected = [], []
    while True:
        row = reader.line_num + 1
        try:
            record = next(reader)
        except StopIteration:
            break
        except csv.Error:
            rejected.append(Rejected(row, "Malformed CSV quoting or field length. Reading stopped."))
            break
        if len(valid) + len(rejected) >= MAX_ROWS:
            raise InputError("CSV exceeds 30,000 data records. Export a smaller time range.")
        if len(record) != len(headers):
            rejected.append(Rejected(row, f"Expected {len(headers)} fields, found {len(record)}."))
            continue
        event, issue = parse_record(row, headers, record)
        if event is None:
            rejected.append(Rejected(row, issue))
        else:
            valid.append(event)
    if not valid and not rejected:
        raise InputError("CSV has a header but no flow records.")
    return valid, rejected


def parse_cidrs(text):
    values = [value for value in re.split(r"[,\s]+", text.strip()) if value]
    if not 1 <= len(values) <= 20:
        raise InputError("Enter between 1 and 20 internal CIDRs.")
    if any("/" not in value for value in values):
        raise InputError("Include a CIDR prefix length, for example 10.0.0.0/8.")
    try:
        return tuple(dict.fromkeys(ipaddress.ip_network(value, strict=True) for value in values))
    except ValueError as exc:
        raise InputError("Use valid CIDR network addresses with no host bits, for IPv4 or IPv6.") from exc


def is_outbound(flow, cidrs):
    source = ipaddress.ip_address(flow.source_ip)
    destination = ipaddress.ip_address(flow.destination_ip)
    return any(source in cidr for cidr in cidrs) and not any(destination in cidr for cidr in cidrs)


def aggregate(flows, cidrs, minutes):
    if not 1 <= minutes <= 60:
        raise InputError("Window duration must be between 1 and 60 minutes.")
    width = timedelta(minutes=minutes)
    groups = defaultdict(list)
    ignored = 0
    for flow in flows:
        if not is_outbound(flow, cidrs):
            ignored += 1
            continue
        start = EPOCH + ((flow.timestamp - EPOCH) // width) * width
        groups[start, flow.source_ip].append(flow)
    return tuple(
        Window(source, start, tuple(sorted(items, key=lambda flow: (flow.timestamp, flow.row))))
        for (start, source), items in sorted(groups.items())
    ), ignored


def reference(values, label):
    return Reference(label, len(values), tuple(np.median(values, axis=0).tolist()),
                     tuple(np.percentile(values, PERCENTILE, axis=0).tolist()))


def analyze(baseline, evaluation, cidrs, minutes, source_label):
    base, ignored_base = aggregate(baseline, cidrs, minutes)
    target, ignored_target = aggregate(evaluation, cidrs, minutes)
    if len(base) < MIN_BASELINE:
        raise InputError(f"Baseline needs at least {MIN_BASELINE} nonempty outbound windows. "
                         f"Found {len(base)}. Import more baseline traffic or use shorter windows.")
    if not target:
        raise InputError("Evaluation has no valid outbound windows. Check the file and internal CIDRs.")
    base_values = [window.values() for window in base]
    model = IsolationForest(n_estimators=TREES, contamination=CONTAMINATION, random_state=SEED, n_jobs=1)
    model.fit(base_values)
    scores = model.decision_function([window.values() for window in target])
    grouped = defaultdict(list)
    for window, values in zip(base, base_values):
        grouped[window.source].append(values)
    shared = reference(base_values, "Shared baseline (fallback)")
    references = {source: reference(values, "Same-source baseline")
                  for source, values in grouped.items() if len(values) >= MIN_SOURCE}
    findings = tuple(Finding(window, float(score), bool(score < 0), references.get(window.source, shared))
                     for window, score in zip(target, scores))
    return Analysis(source_label, len(base), minutes, tuple(map(str, cidrs)), findings,
                    ignored_base, ignored_target)


def comparisons(finding):
    return [{
        "Feature": name, "Observed": value, "Baseline median": median, "Baseline p95": p95,
        "Absolute change from median": abs(value - median), "Ratio to median": value / median if median > 0 else None,
        "Above p95": value > p95,
    } for name, value, median, p95 in zip(FEATURES, finding.window.values(),
                                          finding.reference.medians, finding.reference.p95)]


def supporting_flows(window, feature):
    if feature == "Bytes":
        key = lambda flow: (-flow.bytes, flow.timestamp, flow.row)
    elif feature == "Packets":
        key = lambda flow: (-flow.packets, flow.timestamp, flow.row)
    elif feature == "Distinct destinations":
        key = lambda flow: (flow.destination_ip, flow.timestamp, flow.row)
    else:
        key = lambda flow: (flow.timestamp, flow.row)
    return sorted(window.flows, key=key)


def summarize(finding):
    statements = []
    for row in comparisons(finding):
        if not row["Above p95"]:
            continue
        ratio = row["Ratio to median"]
        description = f"{row['Feature']} reached {row['Observed']:,}, above baseline p95 ({row['Baseline p95']:,.1f})"
        if ratio is not None:
            description += f" and {ratio:.2f}× the median"
        statements.append(description + ".")
        if row["Feature"] in {"Bytes", "Packets"}:
            field = row["Feature"].lower()
            top = supporting_flows(finding.window, row["Feature"])[:3]
            share = sum(getattr(flow, field) for flow in top) / row["Observed"]
            statements.append(f"The top {len(top)} flows contributed {share:.1%} of observed {field}.")
    if not statements:
        statements.append("No individual feature exceeded its comparison baseline p95.")
    return statements


def export_csv(finding):
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=("row", *FIELDS), lineterminator="\n")
    writer.writeheader()
    writer.writerows(flow.export() for flow in finding.window.flows)
    return output.getvalue()


def export_summary(analysis, finding):
    window = finding.window
    return json.dumps({
        "dataset": analysis.source_label, "source": window.source, "window_start_utc": iso(window.start),
        "window_end_exclusive_utc": iso(window.start + timedelta(minutes=analysis.minutes)),
        "detection_settings": {"window_minutes": analysis.minutes, "internal_cidrs": analysis.cidrs,
                               "model": "Isolation Forest", "seed": SEED, "trees": TREES,
                               "contamination": CONTAMINATION, "flag_rule": "decision_function < 0",
                               "baseline_training_windows": analysis.baseline_size},
        "model": {"score": finding.score, "flagged": finding.flagged},
        "baseline_comparison": {"scope": finding.reference.label, "samples": finding.reference.size,
                                "percentile": PERCENTILE, "same_source_minimum": MIN_SOURCE,
                                "features": comparisons(finding),
                                "observations": summarize(finding)},
        "source_rows": [flow.row for flow in window.flows],
    }, ensure_ascii=False, indent=2) + "\n"
