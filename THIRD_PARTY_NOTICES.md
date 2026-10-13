# Third-party notices

Copley's original source code is licensed under Apache-2.0 (see `LICENSE`). The Apache-2.0
license on this repository applies to Copley's own code only. Imported rules, data, and
model artifacts remain under their own terms, summarized below. Nothing here relicenses
third-party material.

## Bundled Sigma rules (SigmaHQ)

Files under `src/copley/rules/library/sigmahq/` are copied verbatim from the SigmaHQ `sigma`
repository and are licensed under the **Detection Rule License (DRL) 1.1**, not Apache-2.0.

- Source: https://github.com/SigmaHQ/sigma
- Pinned revision: `42478221b1a062411b8185732c82caa439271122`
- Path prefix: `rules/windows/process_creation/`
- License: Detection Rule License (DRL) 1.1 — https://github.com/SigmaHQ/Detection-Rule-License
- Access date: 2026-10-13

Bundled rule files (sha256 recorded in `manifests/rules.yaml`):

- `proc_creation_win_certutil_download.yml`
- `proc_creation_win_powershell_base64_encoded_cmd.yml`
- `proc_creation_win_mshta_http.yml`
- `proc_creation_win_wmic_process_creation.yml`
- `proc_creation_win_bitsadmin_download.yml`
- `proc_creation_win_whoami_all_execution.yml`

Note: the Sigma *specification* and logo are public domain; the *rules* are DRL-1.1. See the
SigmaHQ repository's `LICENSE` for the authoritative, current terms.

## Original Copley rules

Files under `src/copley/rules/library/local/` are original work by Backbay Industries,
licensed under Apache-2.0 like the rest of Copley's code.

## External data sources (not redistributed)

Copley does **not** bundle or redistribute any external telemetry. `manifests/sources.yaml`
references the following for opt-in, user-initiated acquisition only:

- **Splunk Attack Data** — https://github.com/splunk/attack_data — Apache-2.0 (repository
  license). Individual captures may carry their own provenance. Pinned revision
  `eac2f8f675ec31a6618003399dcc53641524e673`. Acquired via Git LFS by the user, if at all.

## Research precedent (cited, not vendored)

- **AMIDES** — https://github.com/fkie-cad/amides — GPL-3.0. Copley cites AMIDES as related
  methodology. No AMIDES code is copied into this Apache-2.0 project. Copley's linear
  baseline is an independent scikit-learn implementation, not a reproduction of AMIDES, and
  Copley does not claim AMIDES's enterprise evaluation corpus.

## Model backbone (downloaded on demand, not vendored)

- **answerdotai/ModernBERT-base** — https://huggingface.co/answerdotai/ModernBERT-base —
  Apache-2.0. Not downloaded during the scaffold task. Pinned revision recorded in
  `docs/research.md` and `configs/modernbert-base.yaml`.

## Key Python dependencies

See `pyproject.toml` / `uv.lock` for exact pins. Notable: pySigma and pySigma-backend-sqlite
(the latter is LGPL-3.0; it is a dependency, invoked as a library, not modified or vendored),
scikit-learn (BSD-3-Clause), PyTorch and Transformers (train extra), FastAPI/Uvicorn (serve
extra).
