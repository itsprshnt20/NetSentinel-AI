"""Passive flow analysis dashboard."""
from dataclasses import asdict
from datetime import timedelta
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

from flows import (CONTAMINATION, DEFAULT_CIDRS, FEATURES, SEED, TREES, InputError, analyze,
                   comparisons, export_csv, export_summary, iso, parse_cidrs, parse_csv,
                   summarize, supporting_flows)

SAMPLES = Path(__file__).resolve().parent / "samples"
STYLE = """
<style>
.stApp, [data-testid="stHeader"] { background: #000; }
.stMainBlockContainer { max-width: 75rem; padding-top: 3.4rem; padding-bottom: 4rem; }
.st-key-hero, .st-key-intake, .st-key-overview, .st-key-detail {
    border: 1px solid #293d5b; border-radius: 1.1rem;
    background: #0A1020; padding: clamp(1rem, 2.5vw, 1.6rem);
}
.st-key-hero {
    padding: clamp(1.3rem, 4vw, 2.7rem);
    background: radial-gradient(ellipse at 95% 0%, #1C3B72 0%, #111D35 44%, #050912 77%);
}
.st-key-hero h1 { font-size: clamp(2.55rem, 7vw, 4.8rem); line-height: 1; letter-spacing: -.07em; }
[data-testid="stBaseButton-primary"]:not(:disabled) { background: #91D7FF; border-color: #91D7FF; }
[data-testid="stBaseButton-primary"]:not(:disabled) p { color: #081F35; font-weight: 700; }
.st-key-detail { border-top: 2px solid #E5AC60; }
[data-testid="stMetricValue"] { color: #C3E8FF; font-variant-numeric: tabular-nums; }
[data-testid="stMetric"] { background: #101A2C; border: 1px solid #2B405D; border-radius: .8rem; padding: .8rem; }
[data-testid="stDownloadButton"] button { border-color: #416388; border-radius: .7rem; }
[data-testid="stDownloadButton"] button:hover { color: #C3E8FF; border-color: #91D7FF; }
button:focus-visible, input:focus-visible { outline: 2px solid #91D7FF; outline-offset: 2px; }
</style>
"""


def run_analysis(files, cidr_text, minutes, label):
    st.session_state.analysis = None
    st.session_state.input_errors = []
    st.session_state.rejections = {}
    splits = []
    with st.spinner("Validating flows and scoring outbound windows…"):
        for split, raw in zip(("Baseline", "Evaluation"), files):
            try:
                flows, rejected = parse_csv(raw)
                splits.append(flows)
                st.session_state.rejections[split] = rejected
            except InputError as exc:
                st.session_state.input_errors.append(f"{split}: {exc}")
        if len(splits) != 2:
            return
        try:
            cidrs = parse_cidrs(cidr_text)
            st.session_state.analysis = analyze(*splits, cidrs, minutes, label)
        except InputError as exc:
            st.session_state.input_errors.append(str(exc))


def alert_name(finding):
    detail = ", ".join(row["Feature"] for row in comparisons(finding) if row["Above p95"])
    return f"{finding.window.source} · {iso(finding.window.start)} · {detail or 'Model flag only'}"


def render_overview(result):
    with st.container(key="overview"):
        st.subheader("Traffic overview")
        st.caption(result.source_label)
        columns = st.columns(3)
        columns[0].metric("Baseline windows", result.baseline_size)
        columns[1].metric("Evaluation windows", len(result.findings))
        columns[2].metric("Flagged windows", sum(item.flagged for item in result.findings))
        st.caption(f"{result.minutes}-minute windows · Isolation Forest seed {SEED} · "
                   f"{TREES} trees · contamination {CONTAMINATION:.0%}")
        st.text("Internal CIDRs: " + ", ".join(result.cidrs))
        st.caption(f"Non-outbound rows excluded: {result.baseline_ignored} baseline, "
                   f"{result.evaluation_ignored} evaluation.")
        st.info("Lower Isolation Forest decision scores are more unusual. Scores below zero are "
                "flagged as behavior to investigate. Baseline p95 comparisons are separate.")

        sources = sorted({item.window.source for item in result.findings})
        source = st.selectbox("Filter by source", [None, *sources],
                              format_func=lambda value: value or "All internal sources")
        # The control uses naive datetimes for display. Its documented timezone is UTC.
        first = result.findings[0].window.start.replace(tzinfo=None)
        last = result.findings[-1].window.start.replace(tzinfo=None)
        bounds = (first, last)
        if first < last:
            bounds = st.slider("Window start range (UTC)", first, last, bounds,
                               step=timedelta(minutes=result.minutes), format="YYYY-MM-DD HH:mm")
        filtered = [item for item in result.findings
                    if (source is None or item.window.source == source)
                    and bounds[0] <= item.window.start.replace(tzinfo=None) <= bounds[1]]
        st.subheader("Outbound traffic timeline")
        if filtered:
            chart_rows = [{"UTC window start": item.window.start, "Exact UTC": iso(item.window.start),
                           "Source": item.window.source,
                           "Bytes": item.window.values()[0]} for item in filtered[:3000]]
            chart = alt.Chart(pd.DataFrame(chart_rows)).mark_line(point=True).encode(
                x=alt.X("UTC window start:T", scale=alt.Scale(type="utc")),
                y=alt.Y("Bytes:Q"),
                color=alt.Color("Source:N", scale=alt.Scale(range=["#91D7FF", "#B8A6FF", "#F7C47C", "#77DFCC"])),
                tooltip=[alt.Tooltip("Exact UTC:N"),
                         "Source:N", alt.Tooltip("Bytes:Q", format=",")],
            ).properties(height=245)
            st.altair_chart(chart, use_container_width=True)
            if len(filtered) > 3000:
                st.caption("Showing the first 3,000 chart points. Narrow the filters to inspect a smaller range.")
        else:
            st.info("No windows match these filters.")
        st.subheader("Flagged windows")
        flagged = [item for item in filtered if item.flagged]
        if not flagged:
            st.info("No flagged windows match these filters.")
            return None
        st.dataframe([{
            "Source": item.window.source, "UTC start": iso(item.window.start),
            "Decision score": item.score, "Features above p95": ", ".join(
                row["Feature"] for row in comparisons(item) if row["Above p95"]) or "None",
        } for item in flagged], hide_index=True, use_container_width=True,
            column_config={"Decision score": st.column_config.NumberColumn(format="%.4f")})
        return st.selectbox("Open flagged window", flagged, format_func=alert_name)


def render_detail(result, finding):
    with st.container(key="detail"):
        st.subheader("Alert detail")
        start = finding.window.start
        stop = start + timedelta(minutes=result.minutes)
        st.text(f"{finding.window.source} · {iso(start)} to {iso(stop)} (end exclusive)")
        st.warning(f"Investigate · Isolation Forest decision score {finding.score:.4f}")
        st.subheader("Baseline comparison")
        st.text(f"{finding.reference.label} · {finding.reference.size} reference windows")
        st.caption("Absolute change is the magnitude of the difference. Ratios are unavailable when the median is zero.")
        rows = comparisons(finding)
        display = [{**row, "Ratio to median": ("Unavailable" if row["Ratio to median"] is None
                                              else f"{row['Ratio to median']:.2f}×")} for row in rows]
        st.dataframe(display, hide_index=True, use_container_width=True)
        for item in summarize(finding):
            st.text(item)

        st.subheader("Supporting flows")
        primary = next((row["Feature"] for row in rows if row["Above p95"]), "Flow count")
        feature = st.selectbox("Evidence feature", FEATURES, index=FEATURES.index(primary),
                               key=f"evidence_{finding.window.source}_{iso(start)}")
        flows = supporting_flows(finding.window, feature)
        if feature == "Distinct destinations":
            counts = pd.Series([flow.destination_ip for flow in flows]).value_counts().sort_index()
            st.dataframe(counts.rename("Matching flows").rename_axis("Destination IP").reset_index(),
                         hide_index=True, use_container_width=True)
        st.caption("Rows refer to the evaluation CSV. The CSV export contains the complete selected window.")
        st.dataframe([item.export() for item in flows], hide_index=True, use_container_width=True,
                     column_config={"row": "Source row", "timestamp": "Timestamp (UTC)"})
        one, two = st.columns(2)
        one.download_button("Download supporting CSV", export_csv(finding), "netsentinel-flows.csv",
                            "text/csv", on_click="ignore")
        two.download_button("Download summary JSON", export_summary(result, finding), "netsentinel-summary.json",
                            "application/json", on_click="ignore")


st.set_page_config(page_title="NetSentinel AI", layout="wide")
st.html(STYLE)
with st.container(key="hero"):
    st.title("NetSentinel AI")
    st.write("Compare outbound network flows against a baseline and trace unusual windows to their source rows.")
    st.caption("Passive, local flow analysis · Maintained by Prashant Chauhan")

with st.container(key="intake"):
    st.subheader("Flow inputs")
    left, right = st.columns(2)
    cidr_text = left.text_input("Internal CIDRs", DEFAULT_CIDRS, max_chars=1200,
                               help="Comma- or space-separated networks. Outbound means internal to external.")
    minutes = right.number_input("Window duration (minutes)", min_value=1, max_value=60, value=5)
    if st.button("Load demo", type="primary"):
        run_analysis([(SAMPLES / f"synthetic_{split}.csv").read_bytes()
                      for split in ("baseline", "evaluation")], cidr_text, minutes, "Synthetic demonstration")
    with st.form("uploads"):
        baseline, evaluation = st.columns(2)
        baseline_file = baseline.file_uploader("Baseline CSV", type=["csv"])
        eval_file = evaluation.file_uploader("Evaluation CSV", type=["csv"])
        if st.form_submit_button("Analyze uploaded flows"):
            if baseline_file is None or eval_file is None:
                st.error("Choose separate baseline and evaluation CSV files.")
            else:
                run_analysis((baseline_file.getvalue(), eval_file.getvalue()), cidr_text, minutes, "Uploaded CSVs")
    st.caption("Changes to CIDRs or window duration apply the next time you load or analyze data.")

for message in st.session_state.get("input_errors", []):
    st.error(message)
for split, rejected in st.session_state.get("rejections", {}).items():
    if rejected:
        with st.expander(f"{split} rejected rows ({len(rejected)})", expanded=True):
            st.dataframe([asdict(item) for item in rejected], hide_index=True, use_container_width=True)

result = st.session_state.get("analysis")
if result is None:
    st.info("Load the synthetic demo or choose both CSV files to begin.")
else:
    selected = render_overview(result)
    if selected is not None:
        render_detail(result, selected)
