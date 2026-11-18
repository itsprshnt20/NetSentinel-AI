"""Verify demo, exact evidence exports and input validation using Chromium."""
import csv
import io
import json
import sys
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

URL = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8501").rstrip("/")
SHOTS = Path(sys.argv[2]) if len(sys.argv) > 2 else None
SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def select(page, label, option):
    page.get_by_test_id("stSelectbox").filter(has_text=label).get_by_role("combobox").click()
    page.get_by_role("option", name=option, exact=False).click()


def screenshot(page, locator, filename):
    if SHOTS is not None:
        SHOTS.mkdir(parents=True, exist_ok=True)
        expect(page.get_by_text("Running...", exact=True)).to_be_hidden()
        page.locator(locator).screenshot(path=SHOTS / filename, animations="disabled",
                                         style='[data-testid="stHeader"] { visibility: hidden; }')


def download(page, label):
    expect(page.get_by_text("Running...", exact=True)).to_be_hidden()
    with page.expect_download() as result:
        page.get_by_role("button", name=label).click()
    return result.value.path().read_text(encoding="utf-8")


def main():
    expect.set_options(timeout=45000)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        context = browser.new_context(accept_downloads=True, viewport={"width": 1280, "height": 4550 if SHOTS else 2900})
        external = []

        def local_only(route):
            if route.request.url.startswith(URL + "/"):
                route.continue_()
            else:
                external.append(route.request.url)
                route.abort()

        context.route("**/*", local_only)
        page = context.new_page()
        page.goto(URL)
        expect(page.get_by_role("heading", name="NetSentinel AI")).to_be_visible()
        expect(page.locator(".stApp")).to_have_css("background-color", "rgb(0, 0, 0)")
        page.get_by_role("button", name="Load demo").click()
        expect(page.get_by_role("heading", name="Traffic overview")).to_be_visible()
        expect(page.get_by_test_id("stVegaLiteChart")).to_be_visible()
        expect(page.get_by_role("heading", name="Flagged windows")).to_be_visible()
        screenshot(page, ".st-key-overview", "traffic-overview.png")
        select(page, "Open flagged window", "10.0.0.11 · 2026-08-05T10:25:00Z")
        expect(page.get_by_role("heading", name="Baseline comparison")).to_be_visible()
        expect(page.get_by_text("Same-source baseline · 36 reference windows", exact=True)).to_be_visible()
        expect(page.get_by_text("Bytes reached 167,595", exact=False)).to_be_visible()
        expect(page.get_by_role("heading", name="Supporting flows")).to_be_visible()
        screenshot(page, ".st-key-detail", "alert-evidence.png")

        rows = list(csv.DictReader(io.StringIO(download(page, "Download supporting CSV"))))
        summary = json.loads(download(page, "Download summary JSON"))
        assert len(rows) == 6
        assert [int(row["row"]) for row in rows] == summary["source_rows"]
        assert summary["baseline_comparison"]["features"][0]["Observed"] == 167595
        assert summary["detection_settings"]["baseline_training_windows"] == 72
        assert summary["detection_settings"]["seed"] == 42
        with (SAMPLES / "synthetic_evaluation.csv").open(encoding="utf-8") as file:
            original = list(csv.DictReader(file))
        for row in rows:
            line = int(row.pop("row"))
            assert row == original[line - 2]
        print("PASS: demo, selected byte spike, comparison, exact matching rows and both exports")

        select(page, "Filter by source", "10.0.0.22")
        expect(page.get_by_role("combobox", name="Selected 10.0.0.22 · 2026-08-05T10:10:00Z · Model flag only. Open flagged window")).to_be_visible()
        expect(page.get_by_text("Running...", exact=True)).to_be_hidden()
        select(page, "Open flagged window", "10.0.0.22 · 2026-08-05T11:00:00Z")
        expect(page.get_by_text("Distinct destinations reached 13", exact=False)).to_be_visible()
        select(page, "Evidence feature", "Distinct destinations")
        screenshot(page, ".st-key-detail", "destination-evidence.png")
        summary = json.loads(download(page, "Download summary JSON"))
        assert summary["source"] == "10.0.0.22" and len(summary["source_rows"]) == 13
        print("PASS: source filtering and distinct-destination evidence")

        page.set_viewport_size({"width": 390, "height": 850})
        expect(page.get_by_role("button", name="Load demo")).to_be_visible()
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        uploads = page.locator('input[type="file"]')
        uploads.nth(0).set_input_files(SAMPLES / "synthetic_baseline.csv")
        uploads.nth(1).set_input_files(SAMPLES / "synthetic_evaluation.csv")
        page.get_by_role("button", name="Analyze uploaded flows").click()
        expect(page.get_by_text("Uploaded CSVs", exact=True)).to_be_visible()
        uploads.nth(0).set_input_files({"name": "bad.csv", "mimeType": "text/csv",
                                       "buffer": b"wrong,columns\n1,2"})
        page.get_by_role("button", name="Analyze uploaded flows").click()
        expect(page.get_by_text("Baseline: CSV must contain", exact=False)).to_be_visible()
        assert not external, external
        print("PASS: mobile layout, valid and malformed uploads, no external page requests")
        browser.close()


if __name__ == "__main__":
    main()
