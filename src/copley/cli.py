"""Copley command-line interface.

Commands (see README for exact tested invocations):
  copley doctor
  copley smoke --out artifacts/smoke
  copley data fetch --manifest manifests/sources.yaml --dry-run
  copley data validate --input examples/fixtures.jsonl
  copley data split --input examples/fixtures.jsonl --out artifacts/splits
  copley data adapt --input FILE --source-id ID --out FILE.jsonl
  copley rules list / rules run --input FILE
  copley train --config configs/train-smoke.yaml        (needs --extra train)
  copley train --config configs/modernbert-base.yaml --dry-run
  copley evaluate --artifact DIR --input FILE --out DIR
  copley predict --artifact DIR --input FILE
  copley serve --artifact DIR --host 127.0.0.1          (needs --extra serve)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import typer

app = typer.Typer(
    help="Copley: small cyber decision models (Backbay Industries).", no_args_is_help=True
)
data_app = typer.Typer(
    help="Data preparation: validate, split, fetch, adapt.", no_args_is_help=True
)
rules_app = typer.Typer(help="Sigma rules: list and run.", no_args_is_help=True)
app.add_typer(data_app, name="data")
app.add_typer(rules_app, name="rules")


def _echo(obj: object) -> None:
    typer.echo(json.dumps(obj, indent=2, default=str))


@app.command()
def doctor() -> None:
    """Report Python/dependency versions, SQLite, optional extras, and device availability."""
    import importlib.util
    import platform
    import sqlite3

    def ver(pkg: str) -> str | None:
        try:
            import importlib.metadata as m

            return m.version(pkg)
        except Exception:  # noqa: BLE001
            return None

    report = {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "sqlite_version": sqlite3.sqlite_version,
        "sqlite_regexp_available": _sqlite_has_regexp(),
        "core": {
            p: ver(p)
            for p in [
                "pydantic",
                "typer",
                "scikit-learn",
                "numpy",
                "pysigma",
                "pysigma-backend-sqlite",
            ]
        },
        "extras": {
            "train": {p: ver(p) for p in ["torch", "transformers", "safetensors"]}
            if importlib.util.find_spec("torch")
            else "not installed",
            "serve": {p: ver(p) for p in ["fastapi", "uvicorn"]}
            if importlib.util.find_spec("fastapi")
            else "not installed",
        },
        "device": _device_report(),
    }
    _echo(report)


def _sqlite_has_regexp() -> bool:
    import sqlite3

    conn = sqlite3.connect(":memory:")
    try:
        conn.execute("SELECT 'a' REGEXP 'a'")
        return True
    except sqlite3.OperationalError:
        return False
    finally:
        conn.close()


def _device_report() -> dict:
    try:
        import torch

        return {
            "torch": torch.__version__,
            "cuda": torch.cuda.is_available(),
            "mps": torch.backends.mps.is_available(),
        }
    except ImportError:
        return {"torch": "not installed", "note": "install --extra train for neural path"}


@app.command()
def smoke(out: Path = typer.Option(Path("artifacts/smoke"), help="Output directory")) -> None:
    """Full offline vertical slice on synthetic fixtures (no GPU, network, or downloads)."""
    from copley.pipeline import run_smoke

    result = run_smoke(out)
    typer.secho(
        "SYNTHETIC FIXTURE SMOKE TEST — NOT A DETECTION BENCHMARK",
        fg=typer.colors.MAGENTA,
        bold=True,
        err=True,
    )
    _echo(
        {
            "out_dir": str(result.out_dir),
            "split_counts": result.split_counts,
            "sigma_rules_ok": result.sigma_ok,
            "sigma_rules_failed": result.sigma_failed,
            "reports": {k: str(v) for k, v in result.report_paths.items()},
            "linear_artifact": str(result.linear_dir),
            "example_prediction": result.example_prediction,
        }
    )


@data_app.command("validate")
def data_validate(
    input: Path = typer.Option(..., "--input", help="JSONL of labeled windows"),
) -> None:
    """Validate a dataset and print label/serialization accounting."""
    from copley.data.io import load_labeled
    from copley.data.validate import validate_records

    result = load_labeled(input)
    summary = validate_records(result.records, result.errors)
    _echo(summary.to_dict())
    if result.errors:
        raise typer.Exit(code=1)


@data_app.command("split")
def data_split(
    input: Path = typer.Option(..., "--input"),
    out: Path = typer.Option(..., "--out"),
    seed: int = typer.Option(42, "--seed"),
) -> None:
    """Group-aware split into train/validation/calibration/test."""
    from copley.data.io import load_labeled, write_labeled
    from copley.data.split import split
    from copley.data.validate import account_split

    loaded = load_labeled(input)
    if not loaded.ok:
        _echo({"error": "validation failed", "details": [e.__dict__ for e in loaded.errors]})
        raise typer.Exit(code=1)
    sr = split(loaded.records, seed=seed)
    if not sr.ok:
        _echo({"ok": False, "reason": sr.reason})
        raise typer.Exit(code=2)
    out.mkdir(parents=True, exist_ok=True)
    for part, recs in sr.partitions.items():
        write_labeled(out / f"{part}.jsonl", recs)
    _echo(account_split(sr).to_dict())


@data_app.command("fetch")
def data_fetch(
    manifest: Path = typer.Option(..., "--manifest"),
    dry_run: bool = typer.Option(
        True, "--dry-run/--execute", help="Dry-run prints plan; execute is blocked in this build"
    ),
) -> None:
    """Plan an opt-in external data fetch. Default is dry-run (no network)."""
    from copley.data.fetch import load_source_manifest, plan_fetch

    plans = plan_fetch(load_source_manifest(manifest))
    _echo({"dry_run": dry_run, "sources": [p.to_dict() for p in plans]})
    if not dry_run:
        typer.secho(
            "Execute mode is intentionally not implemented in this build. Acquire enabled "
            "sources manually with `git lfs pull --include=...` at the pinned revision, then "
            "use `copley data adapt`.",
            fg=typer.colors.YELLOW,
        )
        raise typer.Exit(code=3)


@data_app.command("adapt")
def data_adapt(
    input: Path = typer.Option(..., "--input", help="Raw telemetry file"),
    source_id: str = typer.Option(..., "--source-id"),
    out: Path = typer.Option(..., "--out", help="Output JSONL of evidence windows"),
    adapter: str = typer.Option("sysmon_xml", "--adapter"),
) -> None:
    """Convert external telemetry into UNLABELED evidence windows (labeling is separate)."""
    from copley.data.adapters import parse_sysmon_xml
    from copley.data.fetch import ensure_not_pointer

    ensure_not_pointer(input)
    if adapter != "sysmon_xml":
        typer.secho(f"unknown adapter: {adapter}", fg=typer.colors.RED)
        raise typer.Exit(code=2)
    result = parse_sysmon_xml(
        input.read_text(encoding="utf-8", errors="replace"), source_id=source_id
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for w in result.windows:
            fh.write(w.model_dump_json() + "\n")
    _echo(
        {
            "windows": len(result.windows),
            "skipped_non_process_events": result.skipped,
            "out": str(out),
        }
    )


@rules_app.command("list")
def rules_list(manifest: Path | None = typer.Option(None, "--manifest")) -> None:
    """List and compile the pinned Sigma subset."""
    from copley.rules.engine import compile_rules
    from copley.rules.manifest import default_manifest_path, load_rule_manifest

    path = manifest or default_manifest_path()
    entries = load_rule_manifest(path)
    compiled = compile_rules([e.path for e in entries])
    _echo(
        [
            {"rule_id": c.rule_id, "title": c.title, "status": c.status, "detail": c.detail}
            for c in compiled
        ]
    )


@rules_app.command("run")
def rules_run(
    input: Path = typer.Option(..., "--input", help="JSONL of labeled windows or evidence"),
    manifest: Path | None = typer.Option(None, "--manifest"),
) -> None:
    """Execute the Sigma subset against a dataset and print window matches."""
    from copley.data.io import load_evidence
    from copley.rules.engine import compile_rules, run_rules
    from copley.rules.manifest import default_manifest_path, load_rule_manifest

    windows, errors = load_evidence(input)
    entries = load_rule_manifest(manifest or default_manifest_path())
    compiled = compile_rules([e.path for e in entries])
    result = run_rules(windows, compiled)
    _echo(
        {
            "compiled_ok": len(result.ok_rules),
            "compiled_failed": len(result.failed_rules),
            "load_errors": [e.__dict__ for e in errors],
            "matches": {wid: rules for wid, rules in result.window_matched.items()},
        }
    )


@app.command()
def train(
    config: Path = typer.Option(..., "--config", help="Training config YAML"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Describe the run without training"),
    data: Path | None = typer.Option(
        None, "--data", help="Labeled JSONL; default synthetic fixtures"
    ),
) -> None:
    """Train the neural candidate (requires --extra train). Use --dry-run for the plan."""
    try:
        from copley.training.config import TrainingConfig
        from copley.training.neural import dry_run as neural_dry_run
        from copley.training.neural import train as neural_train
    except ImportError:
        typer.secho(
            "neural training needs the `train` extra: uv sync --extra train", fg=typer.colors.RED
        )
        raise typer.Exit(code=4) from None

    cfg = TrainingConfig.from_yaml(config)
    records, val = _load_train_records(data, cfg)
    if dry_run:
        _echo(neural_dry_run(cfg, records))
        return
    if cfg.mode == "tiny":
        typer.secho(
            "Offline tiny smoke training (test_only artifact).", fg=typer.colors.MAGENTA, err=True
        )
    outcome = neural_train(cfg, records, val)
    _echo(
        {
            "model_id": outcome.metadata.model_id,
            "artifact_kind": outcome.metadata.artifact_kind.value,
            "fixture_trained": outcome.metadata.fixture_trained,
            "steps": outcome.steps,
            "final_train_loss": outcome.final_train_loss,
            "best_val_loss": outcome.best_val_loss,
            "wall_seconds": round(outcome.wall_seconds, 2),
            "device": outcome.device,
            "output_dir": str(cfg.output_dir),
        }
    )


def _load_train_records(data: Path | None, cfg):
    from copley.data.split import split

    if data is not None:
        from copley.data.io import load_labeled

        loaded = load_labeled(data)
        if not loaded.ok:
            raise typer.Exit(code=1)
        recs = loaded.records
    else:
        from copley.data.fixtures import build_fixtures

        recs = build_fixtures()
    sr = split(recs, seed=cfg.seed)
    if not sr.ok:
        typer.secho(f"split failed: {sr.reason}", fg=typer.colors.RED)
        raise typer.Exit(code=2)
    return sr.partitions["train"], sr.partitions["validation"]


@app.command()
def evaluate(
    artifact: Path = typer.Option(..., "--artifact", help="Linear or neural artifact dir"),
    input: Path = typer.Option(..., "--input", help="Labeled JSONL (held-out)"),
    out: Path = typer.Option(..., "--out", help="Report output dir"),
    synthetic: bool = typer.Option(
        False, "--synthetic", help="Mark report as synthetic fixture smoke"
    ),
) -> None:
    """Evaluate Sigma + a learned artifact on a labeled dataset and write reports."""
    from copley.data.io import load_labeled
    from copley.evaluation.evaluate import evaluate as run_eval
    from copley.evaluation.report import write_reports
    from copley.models.loader import load_predictor
    from copley.rules.engine import compile_rules, run_rules
    from copley.rules.manifest import default_manifest_path, load_rule_manifest

    loaded = load_labeled(input)
    if not loaded.ok:
        _echo({"error": "validation failed", "details": [e.__dict__ for e in loaded.errors]})
        raise typer.Exit(code=1)
    predictor = load_predictor(artifact)
    entries = load_rule_manifest(default_manifest_path())
    compiled = compile_rules([e.path for e in entries])
    sigma = run_rules([r.evidence for r in loaded.records], compiled)
    kwargs = (
        {"linear": predictor}
        if predictor.metadata.model_type == "linear"
        else {"neural": predictor}
    )
    result = run_eval(
        loaded.records, sigma, dataset_label=input.stem, synthetic_fixture=synthetic, **kwargs
    )
    paths = write_reports(result.to_dict(), out)
    _echo({k: str(v) for k, v in paths.items()})


@app.command()
def predict(
    artifact: Path = typer.Option(..., "--artifact"),
    input: Path = typer.Option(..., "--input", help="JSON (one evidence window) or JSONL"),
) -> None:
    """Predict on evidence windows and print typed predictions as JSONL."""
    from copley.models.loader import load_predictor
    from copley.schemas import EvidenceWindow

    predictor = load_predictor(artifact)
    text = input.read_text(encoding="utf-8").strip()
    windows: list[EvidenceWindow] = []

    def _one(payload: dict) -> EvidenceWindow:
        return EvidenceWindow.model_validate(payload.get("evidence", payload))

    try:
        whole = json.loads(text)
    except json.JSONDecodeError:
        whole = None
    if isinstance(whole, list):
        windows = [_one(x) for x in whole]
    elif isinstance(whole, dict):
        windows = [_one(whole)]
    else:
        # JSONL: one JSON object per line.
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            windows.append(_one(json.loads(line)))
    for w in windows:
        typer.echo(predictor.predict(w).model_dump_json())


@app.command()
def serve(
    artifact: Path = typer.Option(..., "--artifact"),
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8000, "--port"),
) -> None:
    """Serve the decision API + minimal demo (requires --extra serve). Localhost by default."""
    try:
        import uvicorn

        from copley.api import create_app
    except ImportError:
        typer.secho("serving needs the `serve` extra: uv sync --extra serve", fg=typer.colors.RED)
        raise typer.Exit(code=5) from None

    application = create_app(artifact)
    uvicorn.run(application, host=host, port=port)


if __name__ == "__main__":
    app()
