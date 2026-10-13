"""Smoke pipeline, CLI/API parity, fetch dry-run, and adapter behavior."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from copley.cli import app
from copley.data.adapters import parse_sysmon_xml
from copley.data.fetch import ensure_not_pointer, load_source_manifest, plan_fetch
from copley.pipeline import run_smoke

runner = CliRunner()


def test_run_smoke_full_slice(tmp_path):
    result = run_smoke(tmp_path / "smoke")
    assert result.sigma_ok == 8
    assert result.sigma_failed == 0
    assert (tmp_path / "smoke" / "report" / "metrics.json").exists()
    metrics = json.loads((tmp_path / "smoke" / "report" / "metrics.json").read_text())
    assert metrics["synthetic_fixture"] is True
    detectors = {m["detector"] for m in metrics["metrics"]}
    assert {"sigma", "linear"} <= detectors
    assert result.example_prediction["fixture_trained"] is True
    # Run record + source audit are produced and consistent.
    assert result.run_record_path.exists()
    assert result.source_audit["exploratory_only"] is True
    assert "source_label_audit" in metrics
    run_rec = json.loads(result.run_record_path.read_text())
    assert run_rec["split_digests"].keys() == {"train", "validation", "calibration", "test"}


def test_smoke_report_has_banner(tmp_path):
    run_smoke(tmp_path / "smoke")
    md = (tmp_path / "smoke" / "report" / "report.md").read_text()
    assert "SYNTHETIC FIXTURE SMOKE TEST — NOT A DETECTION BENCHMARK" in md


def test_cli_doctor():
    res = runner.invoke(app, ["doctor"])
    assert res.exit_code == 0
    assert "sqlite_version" in res.stdout


def test_cli_validate(tmp_path):
    from copley.data.fixtures import build_fixtures
    from copley.data.io import write_labeled

    p = tmp_path / "f.jsonl"
    write_labeled(p, build_fixtures())
    res = runner.invoke(app, ["data", "validate", "--input", str(p)])
    assert res.exit_code == 0


def test_cli_api_parity(tmp_path):
    import pytest

    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from copley.api import create_app

    smoke = run_smoke(tmp_path / "smoke")
    artifact = smoke.linear_dir

    # CLI prediction
    req_path = tmp_path / "req.json"
    from copley.data.fixtures import build_fixtures

    w = build_fixtures()[0].evidence
    req_path.write_text(json.dumps({"evidence": json.loads(w.model_dump_json())}))
    cli_res = runner.invoke(app, ["predict", "--artifact", str(artifact), "--input", str(req_path)])
    assert cli_res.exit_code == 0
    cli_pred = json.loads(cli_res.stdout.strip().splitlines()[-1])

    # API prediction
    client = TestClient(create_app(artifact))
    api_pred = client.post(
        "/v1/decisions", json={"evidence": json.loads(w.model_dump_json())}
    ).json()

    assert cli_pred["assessment"] == api_pred["assessment"]
    assert cli_pred["score"] == api_pred["score"]
    assert cli_pred["weights_sha256"] == api_pred["weights_sha256"]


def test_api_missing_model(tmp_path):
    import pytest

    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from copley.api import create_app

    client = TestClient(create_app(tmp_path / "absent"))
    assert client.get("/health").json()["status"] == "model_unavailable"
    r = client.post("/v1/decisions", json={"evidence": {}})
    assert r.status_code in (422, 503)


def test_fetch_dry_run_no_network():
    manifest = load_source_manifest(Path("manifests/sources.yaml"))
    plans = plan_fetch(manifest)
    assert plans
    assert all(p.action == "skip_disabled" for p in plans)  # all disabled by default


def test_lfs_pointer_refused(tmp_path):
    import pytest

    from copley.data.fetch import FetchError

    pointer = tmp_path / "x.log"
    pointer.write_text("version https://git-lfs.github.com/spec/v1\noid sha256:abc\nsize 10\n")
    with pytest.raises(FetchError, match="Git LFS pointer"):
        ensure_not_pointer(pointer)


def test_sysmon_adapter_unlabeled():
    sample = (
        "<Event><System><EventID>1</EventID>"
        '<TimeCreated SystemTime="2025-07-29T12:00:00Z"/></System>'
        '<EventData><Data Name="Image">C:\\Windows\\rundll32.exe</Data>'
        '<Data Name="CommandLine">rundll32 a.dll</Data></EventData></Event>'
    )
    res = parse_sysmon_xml(sample, source_id="t")
    assert len(res.windows) == 1
    assert res.windows[0].anchor.image.endswith("rundll32.exe")
