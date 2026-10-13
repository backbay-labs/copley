# Research notes and pinned versions

Access date for all checks below: **2026-10-13**. Re-verify before any real training run.

## Decisions (reversible)

- **Python 3.12** as the supported dev version. The dependency stack resolved cleanly; see
  `uv.lock`. (Transformers 5.x / torch 2.14 also support 3.12.)
- **Neural backbone:** `answerdotai/ModernBERT-base` (Apache-2.0), fine-tuned for sequence
  classification. Verified pinned revision (HF `main` at check time):
  `8949b909ec900327062f0ebf497f51aef5e6f0c8`. The repo ships `model.safetensors`. No remote
  code execution is required (`trust_remote_code=false`). We confirmed, offline, that a tiny
  `ModernBertConfig` builds, trains (forward/backward), and round-trips through safetensors on
  CPU, and that `transformers.ModernBertForSequenceClassification` is importable at the pinned
  library version. We did **not** download or run the full pretrained backbone (that requires
  a network download; not authorized under the $0 scaffold task). [R1, R2]
- **Cheap learned baseline:** an independent scikit-learn pipeline — character TF-IDF
  (`char_wb`, n-grams 2–5) + logistic regression. Fit only on the training split. This is our
  own choice, not a reproduction of AMIDES. [R4, R5]
- **Rules baseline:** real pySigma + the SQLite backend (`sqliteBackend`). We compile a pinned
  rule subset and execute the generated SQL against an in-memory SQLite table of the same
  normalized events the models see. We do **not** reimplement Sigma semantics with substring
  checks. [R3]
- **First external-data candidate:** a small selected subset of Splunk Attack Data, acquired
  selectively via Git LFS by the user. Not downloaded here. [R6]

## Verified dependency versions (from `uv.lock`)

| Package | Version | Notes |
|---|---|---|
| pysigma | 2.0.1 | backend requires pySigma 2.x |
| pysigma-backend-sqlite | 2.1.0 | `sqliteBackend`; backend 2.0.0 was the last for pySigma 1.5 |
| pydantic | 2.14.1 | |
| typer | 0.27.3 | |
| scikit-learn | 1.9.1 | |
| numpy | 2.5.4 | |
| pyyaml | 6.0.3 | safe loader used |
| torch | 2.14.1 | train extra; CPU/MPS verified, no CUDA on dev host |
| transformers | 5.19.0 | train extra; ModernBERT present |
| safetensors | 0.8.0 | weights format |
| fastapi | 0.143.0 | serve extra |
| uvicorn | 0.54.0 | serve extra |

We intentionally do **not** install the `pysigma-pipeline-sysmon` / `-windows` packages: at
check time they still declared `pysigma<2`, which conflicts with the backend's pySigma 2.x
requirement. Instead the logsource mapping is explicit in Copley (`src/copley/rules/engine.py`):
only `process_creation`/`windows` rules are applied, and rule field names map directly to our
normalized columns. This is a documented deviation from the backend README's pipeline example.

## Licensing findings

- **SigmaHQ rules**: Detection Rule License (DRL) 1.1 (the Sigma *spec* and logo are public
  domain; the *rules* are DRL-1.1). Pinned repo revision
  `42478221b1a062411b8185732c82caa439271122`. [R7]
- **pySigma-backend-sqlite**: LGPL-3.0 (used as an unmodified library dependency).
- **Splunk Attack Data**: Apache-2.0 repository license; pinned revision
  `eac2f8f675ec31a6618003399dcc53641524e673`. [R6]
- **AMIDES**: GPL-3.0 — cited only; no code copied into this Apache-2.0 project. [R4]
- **ModernBERT-base**: Apache-2.0. [R1]

## Scope relationships

Jev and the OpenAI Decisions API inform the *bounded-decision interface* only, not our
architecture or expected accuracy. Clef is related open decision-model work; we did not switch
to a larger backbone to imitate its API. [R11–R13]

## References

[R1] https://huggingface.co/answerdotai/ModernBERT-base
[R2] https://huggingface.co/docs/transformers/model_doc/modernbert
[R3] https://github.com/SigmaHQ/pySigma-backend-sqlite
[R4] https://github.com/fkie-cad/amides
[R5] https://www.usenix.org/conference/usenixsecurity24/presentation/uetz
[R6] https://github.com/splunk/attack_data
[R7] https://github.com/SigmaHQ/sigma/blob/master/LICENSE
[R8] https://docs.astral.sh/uv/guides/projects/
[R9] https://scikit-learn.org/stable/modules/generated/sklearn.model_selection.StratifiedGroupKFold.html
[R10] https://scikit-learn.org/stable/modules/calibration.html
[R11] https://typesafe.ai/blog/introducing-system-one-models-and-jev
[R12] https://developers.openai.com/api/docs/guides/decisions
[R13] https://blog.cloudflare.com/clef-decision-models/
