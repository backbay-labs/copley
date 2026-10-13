"""Render Markdown/HTML reports from evaluation JSON. No metric is computed here."""

from __future__ import annotations

import html
import json
from pathlib import Path

SMOKE_BANNER = "SYNTHETIC FIXTURE SMOKE TEST — NOT A DETECTION BENCHMARK"


def _fmt(v: object) -> str:
    if v is None:
        return "n/a"
    if isinstance(v, float):
        return f"{v:.3f}"
    return str(v)


def render_markdown(result: dict) -> str:
    lines: list[str] = []
    if result.get("synthetic_fixture"):
        lines += [f"> **{SMOKE_BANNER}**", ""]
    lines += [f"# Copley evaluation: {result['dataset_label']}", ""]

    d = result["denominators"]
    lines += ["## Denominators", ""]
    for k, v in d.items():
        lines.append(f"- **{k}**: {v}")
    lines.append("")

    lines += ["## Detector comparison", ""]
    cols = [
        "detector",
        "kind",
        "tp",
        "fp",
        "tn",
        "fn",
        "precision",
        "recall_scored",
        "recall_all_positives",
        "average_precision",
        "abstentions",
        "fp_per_10k_benign",
    ]
    lines.append("| " + " | ".join(cols) + " |")
    lines.append("|" + "|".join(["---"] * len(cols)) + "|")
    for m in result["metrics"]:
        lines.append("| " + " | ".join(_fmt(m.get(c)) for c in cols) + " |")
    lines.append("")

    for m in result["metrics"]:
        notes = [n for n in m.get("notes", []) if n]
        if notes:
            lines.append(f"- **{m['detector']}**: " + "; ".join(notes))
    lines.append("")

    if result.get("disagreements"):
        lines += ["## Disagreements (Sigma vs primary learned model)", ""]
        for bucket, info in result["disagreements"].items():
            lines.append(
                f"- **{bucket}**: {info['count']} — {', '.join(info['window_ids']) or 'none'}"
            )
        lines.append("")

    lines += ["## Thresholds", ""]
    for k, v in result["thresholds"].items():
        lines.append(f"- **{k}**: {_fmt(v)} (frozen before test evaluation)")
    lines.append("")

    lines += [
        "## Interpretation limits",
        "",
        "- Scores are uncalibrated unless a calibration artifact is attached; do not read them as probabilities.",
        "- False-positive counts are over the evaluated benign sample only; zero observed FP is not a zero FP rate.",
        "- Sigma results reflect the selected pinned subset, not full Sigma coverage.",
        "- A model-only detection is a miss by this subset, not proof all Sigma rules would miss it.",
    ]
    if result.get("synthetic_fixture"):
        lines += [
            "- These numbers measure wiring on synthetic fixtures and carry no detection-performance meaning."
        ]
    return "\n".join(lines) + "\n"


def render_html(result: dict) -> str:
    md_as_text = render_markdown(result)
    banner = ""
    if result.get("synthetic_fixture"):
        banner = f'<div class="banner">{html.escape(SMOKE_BANNER)}</div>'
    rows = ""
    cols = [
        "detector",
        "kind",
        "tp",
        "fp",
        "tn",
        "fn",
        "precision",
        "recall_scored",
        "recall_all_positives",
        "average_precision",
        "abstentions",
        "fp_per_10k_benign",
    ]
    header = "".join(f"<th>{html.escape(c)}</th>" for c in cols)
    for m in result["metrics"]:
        cells = "".join(f"<td>{html.escape(_fmt(m.get(c)))}</td>" for c in cols)
        rows += f"<tr>{cells}</tr>"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Copley evaluation — {html.escape(result["dataset_label"])}</title>
<style>
  body {{ font-family: ui-serif, Georgia, serif; color:#1a1420; background:#faf8f5; max-width:60rem; margin:2rem auto; padding:0 1.5rem; }}
  .banner {{ background:#2a1a2e; color:#f5efe8; padding:.6rem 1rem; border-radius:4px; letter-spacing:.04em; font-weight:600; }}
  table {{ border-collapse:collapse; width:100%; font-size:.9rem; }}
  th,td {{ border:1px solid #d8cfc4; padding:.35rem .5rem; text-align:right; }}
  th:first-child, td:first-child {{ text-align:left; }}
  h1,h2 {{ font-weight:600; }} a {{ color:#6a3d7a; }}
  pre {{ white-space:pre-wrap; background:#f1ebe3; padding:1rem; border-radius:4px; font-family:ui-monospace,monospace; }}
</style></head>
<body>
{banner}
<h1>Copley evaluation — {html.escape(result["dataset_label"])}</h1>
<table><thead><tr>{header}</tr></thead><tbody>{rows}</tbody></table>
<h2>Full report</h2>
<pre>{html.escape(md_as_text)}</pre>
</body></html>
"""


def write_reports(result: dict, out_dir: Path) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "json": out_dir / "metrics.json",
        "markdown": out_dir / "report.md",
        "html": out_dir / "report.html",
    }
    paths["json"].write_text(json.dumps(result, indent=2), encoding="utf-8")
    paths["markdown"].write_text(render_markdown(result), encoding="utf-8")
    paths["html"].write_text(render_html(result), encoding="utf-8")
    return paths
