"""Server-rendered demo page. All telemetry is HTML-escaped; no external fetches."""

from __future__ import annotations

import html

from copley.data.fixtures import build_fixtures
from copley.data.serialize import serialize
from copley.models.base import BasePredictor
from copley.rules.engine import CompiledRule, run_rules
from copley.schemas import Label

_STYLE = """
  :root { --ink:#1a1420; --paper:#faf8f5; --plum:#6a3d7a; --line:#d8cfc4; --muted:#6b6358; }
  * { box-sizing:border-box; }
  body { font-family: ui-serif, Georgia, serif; color:var(--ink); background:var(--paper);
         max-width:68rem; margin:0 auto; padding:2rem 1.5rem; line-height:1.5; }
  header { border-bottom:1px solid var(--line); padding-bottom:1rem; margin-bottom:1.5rem; }
  h1 { font-weight:600; margin:0; letter-spacing:.01em; }
  .sub { color:var(--muted); font-size:.95rem; }
  .badge { display:inline-block; font-family:ui-monospace,monospace; font-size:.72rem;
           border:1px solid var(--plum); color:var(--plum); border-radius:3px; padding:.1rem .45rem;
           letter-spacing:.05em; text-transform:uppercase; }
  .badge.warn { border-color:#8a5a00; color:#8a5a00; }
  .card { border:1px solid var(--line); border-radius:6px; padding:1rem 1.2rem; margin:1rem 0; }
  .grid { display:grid; grid-template-columns:1fr 1fr; gap:1.2rem; }
  pre { white-space:pre-wrap; word-break:break-word; background:#f1ebe3; padding:.8rem;
        border-radius:4px; font-family:ui-monospace,monospace; font-size:.8rem; margin:0; }
  table { border-collapse:collapse; width:100%; font-size:.88rem; }
  td,th { border:1px solid var(--line); padding:.3rem .5rem; text-align:left; }
  .verdict { font-weight:600; }
  .suspicious { color:#9a2b2b; } .likely_benign { color:#2b6a3d; } .abstain { color:var(--muted); }
  .unavail { color:#8a5a00; }
  footer { color:var(--muted); font-size:.82rem; margin-top:2rem; border-top:1px solid var(--line); padding-top:1rem; }
  @media (max-width:40rem){ .grid{grid-template-columns:1fr;} }
"""


def _verdict_html(predictor: BasePredictor | None, window) -> str:
    if predictor is None:
        return '<span class="unavail">model unavailable</span>'
    p = predictor.predict(window)
    cls = p.assessment.value
    score = "n/a" if p.score is None else f"{p.score:.3f}"
    warn = (
        (" · " + ", ".join(html.escape(w) for w in p.quality_warnings))
        if p.quality_warnings
        else ""
    )
    reason = f" · {html.escape(p.abstention_reason)}" if p.abstention_reason else ""
    return (
        f'<span class="verdict {cls}">{html.escape(cls)}</span> '
        f"(score {score}, uncalibrated){warn}{reason}"
    )


def _example_card(record, predictor, compiled) -> str:
    w = record.evidence
    ser = serialize(w)
    text = ser.text or "(not serializable)"
    sigma = run_rules([w], compiled)
    matched = sigma.window_matched.get(w.window_id, [])
    sigma_html = (
        "matched: " + ", ".join(html.escape(r) for r in matched)
        if matched
        else '<span class="unavail">no selected rule matched</span>'
    )
    return f"""
    <div class="card">
      <div><strong>{html.escape(w.window_id)}</strong> &middot;
        annotation label: <code>{html.escape(record.annotation.label.value)}</code> &middot;
        provenance: <code>{html.escape(record.annotation.provenance.category.value)}</code></div>
      <div class="grid">
        <div>
          <div class="sub">Model input (serialized evidence)</div>
          <pre>{html.escape(text)}</pre>
        </div>
        <div>
          <div class="sub">Results</div>
          <table>
            <tr><th>Sigma (selected subset)</th><td>{sigma_html}</td></tr>
            <tr><th>Learned model</th><td>{_verdict_html(predictor, w)}</td></tr>
          </table>
        </div>
      </div>
    </div>
    """


def render_demo_page(
    predictor: BasePredictor | None,
    compiled: list[CompiledRule],
    load_error: str | None,
) -> str:
    fixtures = build_fixtures()
    # Disclosed selection rule: first malicious and first benign fixture by id order.
    mal = next(r for r in fixtures if r.annotation.label is Label.malicious)
    ben = next(r for r in fixtures if r.annotation.label is Label.benign)

    if predictor is None:
        status = (
            f'<span class="badge warn">model unavailable</span> {html.escape(load_error or "")}'
        )
    else:
        md = predictor.metadata
        kind = html.escape(md.artifact_kind.value)
        fx = '<span class="badge warn">fixture-trained</span>' if md.fixture_trained else ""
        status = (
            f'<span class="badge">{html.escape(md.model_type)}</span> '
            f'<span class="badge">{kind}</span> {fx} '
            f'<span class="sub">{html.escape(md.model_id)} · threshold '
            f"{md.threshold if md.threshold is not None else '0.5 (default)'} · "
            f"calibration: {html.escape(md.calibration.status.value)}</span>"
        )

    cards = _example_card(mal, predictor, compiled) + _example_card(ben, predictor, compiled)
    rules_ok = len([c for c in compiled if c.status == "ok"])
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Copley — Backbay Industries</title><style>{_STYLE}</style></head>
<body>
<header>
  <h1>Copley</h1>
  <div class="sub">An open research project for small cyber decision models · Backbay Industries</div>
</header>
<div class="card">
  <div>Artifact: {status}</div>
  <div class="sub" style="margin-top:.4rem">Task: <code>process_execution.suspicious.v1</code> ·
  Sigma: {rules_ok} compiled rules (selected subset, not full coverage)</div>
</div>
<p class="sub">Two examples below show the evidence a model sees next to the selected Sigma rules
and the learned model's verdict. Examples are drawn from synthetic fixtures using a disclosed
rule (first malicious, first benign). Scores are uncalibrated.</p>
{cards}
<footer>
  Fixture-trained models are smoke tests, not detectors. Scores are not probabilities unless a
  calibration artifact is attached. Sigma results reflect a selected pinned subset. Running this
  server publicly requires additional authentication and operational controls; it binds to
  localhost by default and does not log raw telemetry.
</footer>
</body></html>
"""
