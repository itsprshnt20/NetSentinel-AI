import csv
import io
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from sklearn.ensemble import IsolationForest

from flows import (DEFAULT_CIDRS, FIELDS, Finding, InputError, Reference, aggregate, analyze, comparisons,
                   export_csv, export_summary, is_outbound, iso, parse_cidrs, parse_csv, supporting_flows)
from samples.generate_flows import generate

SAMPLES = Path(__file__).resolve().parents[1] / "samples"
HEADER = ",".join(FIELDS) + "\n"


class FlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cidrs = parse_cidrs(DEFAULT_CIDRS)
        cls.baseline = parse_csv((SAMPLES / "synthetic_baseline.csv").read_bytes())[0]
        cls.evaluation = parse_csv((SAMPLES / "synthetic_evaluation.csv").read_bytes())[0]
        cls.result = analyze(cls.baseline, cls.evaluation, cls.cidrs, 5, "Synthetic")
        cls.byte_alert = next(item for item in cls.result.findings
                              if iso(item.window.start) == "2026-08-05T10:25:00Z"
                              and item.window.source == "10.0.0.11")

    def test_invalid_rows_keep_original_line_numbers(self):
        flows, rejected = parse_csv((HEADER +
            "bad,zz,invalid,65536,FTP,-1,2.5\n"
            "2026-08-05T15:30:00+05:30,10.0.0.11,203.0.113.1,65535,udp,0,0\n"
            "not,enough,columns\n"
            "2026-08-05T10:05:00,10.0.0.11,203.0.113.1,0,ICMP,10,2").encode())
        self.assertEqual([row.row for row in rejected], [2, 4])
        for name in FIELDS:
            self.assertIn(name, rejected[0].reason)
        self.assertEqual([row.row for row in flows], [3, 5])
        self.assertEqual(iso(flows[0].timestamp), "2026-08-05T10:00:00Z")
        self.assertEqual(iso(flows[1].timestamp), "2026-08-05T10:05:00Z")
        with self.assertRaisesRegex(InputError, "no flow records"):
            parse_csv(HEADER.encode())
        with self.assertRaisesRegex(InputError, "unique columns"):
            parse_csv(b"wrong,columns\n1,2")

    def test_boundary_and_empty_windows(self):
        flows, _ = parse_csv((HEADER +
            "2026-08-05T10:04:59.999999Z,10.0.0.11,203.0.113.1,443,TCP,20,2\n"
            "2026-08-05T10:05:00Z,10.0.0.11,203.0.113.1,443,TCP,30,3\n"
            "2026-08-05T10:20:00Z,10.0.0.11,203.0.113.1,443,TCP,40,4").encode())
        windows, _ = aggregate(reversed(flows), self.cidrs, 5)
        self.assertEqual([window.start.minute for window in windows], [0, 5, 20])
        self.assertEqual([window.flows[0].row for window in windows], [2, 3, 4])

    def test_direction_ipv4_and_ipv6(self):
        cidrs = parse_cidrs("10.0.0.0/8 fd00::/8")
        flow = self.byte_alert.window.flows[0]
        self.assertTrue(is_outbound(flow, cidrs))
        self.assertFalse(is_outbound(replace(flow, destination_ip="10.0.0.22"), cidrs))
        self.assertFalse(is_outbound(replace(flow, source_ip="203.0.113.2"), cidrs))
        self.assertTrue(is_outbound(replace(flow, source_ip="fd00::1", destination_ip="2001:db8::1"), cidrs))
        self.assertFalse(is_outbound(replace(flow, source_ip="fd00::1", destination_ip="fd00::2"), cidrs))
        with self.assertRaisesRegex(InputError, "host bits"):
            parse_cidrs("10.0.0.1/8")

    def test_separation_and_reproducible_scores(self):
        trained = []

        class RecordingForest(IsolationForest):
            def fit(self, values, *args, **kwargs):
                trained.extend(values)
                return super().fit(values, *args, **kwargs)

        with patch("flows.IsolationForest", RecordingForest):
            repeated = analyze(reversed(self.baseline), reversed(self.evaluation), self.cidrs, 5, "Synthetic")
        base, _ = aggregate(self.baseline, self.cidrs, 5)
        self.assertEqual(trained, [item.values() for item in base])
        self.assertEqual(repeated, self.result)
        self.assertTrue(self.byte_alert.flagged)
        self.assertTrue(any(item.flagged and item.window.values()[2] == 13 for item in self.result.findings))

    def test_insufficient_or_empty_outbound_data(self):
        with self.assertRaisesRegex(InputError, "at least 24"):
            analyze(self.baseline[:3], self.evaluation, self.cidrs, 5, "Test")
        with self.assertRaisesRegex(InputError, "no valid outbound windows"):
            analyze(self.baseline, [], self.cidrs, 5, "Test")

    def test_fallback_and_zero_median(self):
        unseen = [replace(flow, source_ip="10.0.0.99") for flow in self.byte_alert.window.flows]
        [result] = analyze(self.baseline, unseen, self.cidrs, 5, "Test").findings
        self.assertEqual(result.reference.label, "Shared baseline (fallback)")
        self.assertEqual(result.reference.size, 72)
        self.assertEqual(self.byte_alert.reference.label, "Same-source baseline")
        self.assertEqual(self.byte_alert.reference.size, 36)
        reference = Reference("Synthetic zero", 24, (0, 0, 1, 1), (0, 0, 1, 1))
        finding = Finding(self.byte_alert.window, -0.1, True, reference)
        row = comparisons(finding)[0]
        self.assertIsNone(row["Ratio to median"])
        self.assertEqual(row["Absolute change from median"], row["Observed"])

    def test_evidence_ranking_export_and_summary_are_selected_window_only(self):
        window = self.byte_alert.window
        for name, field in (("Bytes", "bytes"), ("Packets", "packets")):
            scores = [getattr(item, field) for item in supporting_flows(window, name)]
            self.assertEqual(scores, sorted(scores, reverse=True))
        destinations = [item.destination_ip for item in supporting_flows(window, "Distinct destinations")]
        self.assertEqual(destinations, sorted(destinations))
        parsed = list(csv.DictReader(io.StringIO(export_csv(self.byte_alert))))
        self.assertEqual([int(row["row"]) for row in parsed], [flow.row for flow in window.flows])
        self.assertTrue(all(row["source_ip"] == window.source for row in parsed))
        for row, original in zip(parsed, window.flows):
            self.assertEqual(row, {key: str(value) for key, value in original.export().items()})
        summary = json.loads(export_summary(self.result, self.byte_alert))
        self.assertEqual(summary["source_rows"], [flow.row for flow in window.flows])
        self.assertEqual(summary["baseline_comparison"]["features"][0]["Observed"], window.values()[0])
        self.assertEqual(summary["detection_settings"]["seed"], 42)

    def test_generator_reproduces_both_fixtures(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            generate(directory)
            for file in directory.iterdir():
                self.assertEqual(file.read_bytes(), (SAMPLES / file.name).read_bytes())
