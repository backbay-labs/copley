# Data plan

## Current state

The only data shipped in this repository is a tiny corpus of **original synthetic fixtures**
(`src/copley/data/fixtures.py`, exported to `examples/fixtures.jsonl`). It exists for wiring
tests only. Every fixture is `label_source = synthetic_fixture`-adjacent (controlled synthetic
examples) and every report derived from it is labeled
**SYNTHETIC FIXTURE SMOKE TEST — NOT A DETECTION BENCHMARK**.

Fixture counts (as generated): 27 windows — 12 malicious (controlled-execution templates:
certutil download, base64 PowerShell, mshta http, wmic process-create) and 15 benign
(git, python, msbuild, admin PowerShell, plain whoami). Variants of each template share a
`template_id` group.

No external telemetry has been downloaded or redistributed.

## Positive-example definition

A **positive** (`malicious`) window is one where event/window-level evidence supports a
malicious assessment, established by one of: reviewed evidence, known controlled execution, or
a weak rule label (kept separate from independently reviewed test examples). Provenance
categories are distinct: `synthetic_fixture`, `controlled_attack_execution`, `real_intrusion`,
`benign_operations`, `unknown`. **Controlled attack execution and real unauthorized intrusion
are different categories.** Unlabeled data is not benign data.

## Acquisition (opt-in, not run here)

`manifests/sources.yaml` lists external candidates (Splunk Attack Data captures), all
`enabled: false`. `copley data fetch --dry-run` prints the plan and accesses no network.
Actual acquisition is the user's manual `git lfs pull --include=...` at the pinned revision;
Copley then adapts files via `copley data adapt` (Sysmon XML → unlabeled evidence). The adapter
never assigns a malicious label.

The sha256 values recorded for external files are the **Git LFS object ids** from the pointer
files at the pinned revision (verified 2026-10-13), not content hashes of downloaded bytes.

## Critical anti-leakage constraints (enforced or documented)

1. **Do not label every event in a capture malicious.** The adapter emits `unlabeled`
   windows; labeling is a separate reviewed step.
2. **Do not call agreement with Sigma "independent accuracy"** if you trained on Sigma matches.
   The linear/neural models train on human/controlled labels, not on Sigma output.
3. **Source/label correlation is a known risk.** If all benign come from one source and all
   malicious from another, the result is a source classifier. With only unmatched sources,
   label the experiment *exploratory* and block strong release claims. (See `docs/evaluation.md`.)
4. **Group before splitting.** `split.py` groups by run/incident/scenario/host/template (or a
   content hash fallback) and keeps a group wholly within one partition. Near-duplicates are
   collapsed within a group. Duplicate handling is decided from input structure, never test
   outcomes. A leakage test asserts no group spans partitions.
5. **Four disjoint partitions**: train / validation / calibration / test. Vectorizers and model
   params fit on train only; calibration fits on calibration only; thresholds are chosen on
   validation; final test is untouched until evaluation.
6. **Per-split accounting** records source, class, group, and future-event counts
   (`copley data split` / `validation.json`). Chronological or source-held-out tests can be
   added when the metadata supports them; we do not fabricate that metadata.
7. **Insufficient groups/classes → visible `insufficient_data`.** The splitter refuses to fall
   back to a random row split (tested).

## Growth target

A planning target of ~5,000–20,000 reviewed windows, reached only with suitable independent
examples — **not** by duplicating templates. This is a target, not an acceptance requirement.
