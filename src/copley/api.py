"""Minimal FastAPI app: health, model metadata, decisions, and a same-origin demo page.

Uses the SAME prediction code as the CLI (`load_predictor`). Requires explicit artifact
configuration, validates bounded payloads (via the evidence schema), binds to localhost by
default (set in the CLI), does not log raw telemetry, and never fabricates output when a
model is unavailable. Public exposure requires additional authentication and operational
controls — see the docstring banner and README.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, ConfigDict

from copley.models.artifact import ArtifactError
from copley.models.loader import load_predictor
from copley.rules.engine import compile_rules, run_rules
from copley.rules.manifest import default_manifest_path, load_rule_manifest
from copley.schemas import EvidenceWindow, Prediction
from copley.web.page import render_demo_page


class DecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    evidence: EvidenceWindow


def create_app(artifact_dir: Path | str) -> FastAPI:
    artifact_dir = Path(artifact_dir)
    app = FastAPI(title="Copley Decision API", version="0.1.0")

    try:
        predictor = load_predictor(artifact_dir)
        load_error: str | None = None
    except (ArtifactError, FileNotFoundError) as exc:
        predictor = None
        load_error = str(exc)

    entries = load_rule_manifest(default_manifest_path())
    compiled = compile_rules([e.path for e in entries])

    @app.get("/health")
    def health() -> dict:
        return {
            "status": "ok" if predictor is not None else "model_unavailable",
            "model_loaded": predictor is not None,
            "model_error": load_error,
            "sigma_rules_ok": len([c for c in compiled if c.status == "ok"]),
        }

    @app.get("/v1/model")
    def model_info() -> dict:
        if predictor is None:
            raise HTTPException(status_code=503, detail=f"model unavailable: {load_error}")
        md = predictor.metadata
        return {
            "model_id": md.model_id,
            "model_type": md.model_type,
            "artifact_kind": md.artifact_kind.value,
            "fixture_trained": md.fixture_trained,
            "task_id": md.task_id,
            "threshold": md.threshold,
            "calibration_status": md.calibration.status.value,
            "weights_sha256": md.weights_sha256,
            "preprocessing_version": md.preprocessing_version,
        }

    @app.post("/v1/decisions", response_model=Prediction)
    def decide(request: DecisionRequest) -> Prediction:
        if predictor is None:
            raise HTTPException(status_code=503, detail=f"model unavailable: {load_error}")
        return predictor.predict(request.evidence)

    @app.get("/v1/sigma")
    def sigma_decision(window_json: str) -> dict:
        import json

        try:
            window = EvidenceWindow.model_validate(json.loads(window_json))
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        result = run_rules([window], compiled)
        return {
            "window_id": window.window_id,
            "matched": result.matched(window.window_id),
            "rules": result.window_matched.get(window.window_id, []),
        }

    @app.get("/", response_class=HTMLResponse)
    def demo() -> str:
        return render_demo_page(predictor, compiled, load_error)

    return app
