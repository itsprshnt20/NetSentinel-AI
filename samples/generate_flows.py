"""Recreate the bundled synthetic flow CSVs with a fixed standard-library seed."""
import csv
from datetime import datetime, timedelta, timezone
from pathlib import Path
from random import Random

ROOT = Path(__file__).resolve().parent
HEADER = ("timestamp", "source_ip", "destination_ip", "destination_port", "protocol", "bytes", "packets")
SOURCES = ("10.0.0.11", "10.0.0.22")


def generate(root=ROOT):
    rng = Random(42)
    epoch = datetime(2026, 8, 4, 10, tzinfo=timezone.utc)
    for name, day, count in (("baseline", 0, 36), ("evaluation", 1, 20)):
        rows = []
        for index in range(count):
            bucket = epoch + timedelta(days=day, minutes=5 * index)
            for source in SOURCES:
                flows = rng.randint(5, 7)
                distinct = rng.randint(2, 4)
                if day and index == 12 and source == SOURCES[1]:
                    flows, distinct = 13, 13
                for offset in range(flows):
                    size, packets = rng.randint(800, 1600), rng.randint(12, 25)
                    if day and index == 5 and source == SOURCES[0] and offset < 3:
                        size *= 40
                        packets *= 5
                    t = (bucket + timedelta(seconds=15 + offset * 12)).isoformat().replace("+00:00", "Z")
                    rows.append((t, source, f"203.0.113.{10 + offset % distinct}", 443, "TCP", size, packets))
            rows.append((bucket.isoformat().replace("+00:00", "Z"), "198.51.100.2",
                         SOURCES[0], 443, "TCP", 900, 12))
        rng.shuffle(rows)
        with (root / f"synthetic_{name}.csv").open("w", encoding="utf-8", newline="") as file:
            writer = csv.writer(file, lineterminator="\n")
            writer.writerow(HEADER)
            writer.writerows(rows)


if __name__ == "__main__":
    generate()
