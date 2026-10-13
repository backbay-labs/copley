# Data card

> The only dataset in this repository is **original synthetic fixtures** for wiring tests. No
> external telemetry is bundled or redistributed.

## Synthetic fixtures (`copley-synthetic-fixtures-v1`)

- **Source:** hand-authored in `src/copley/data/fixtures.py` by Backbay Industries. License:
  Apache-2.0. Redistribution: allowed (it is original).
- **Provenance categories:** `controlled_attack_execution` (synthetic, LOLBIN-style malicious
  templates) and `benign_operations` (ordinary admin/dev commands). These are **synthetic**, not
  captured telemetry.
- **Size:** 27 windows — 12 malicious, 15 benign — across 9 template groups.
- **Grouping:** every variant of a template shares a `template_id` (and `scenario_id`) so
  variants never split across train/test.
- **Label definition:** labels are assigned by construction (`known_controlled_execution`), only
  because the examples are synthetic and authored with known intent. This is **not** a model for
  how real labels are produced.

### What constitutes a positive example

A positive (`malicious`) window has event/window-level evidence supporting a malicious
assessment. Acceptable label sources: reviewed evidence, known controlled execution, weak rule
label (kept separate from reviewed test examples). **Controlled attack execution ≠ real
unauthorized intrusion.** Unlabeled ≠ benign.

## External sources (referenced, not included)

Listed in `manifests/sources.yaml`, all `enabled: false`:

| id | repo | revision | license | label availability | status |
|---|---|---|---|---|---|
| splunk-attack-data-rundll32-tmp | splunk/attack_data | eac2f8f… | Apache-2.0 | unlabeled_requires_review | disabled, unverified |
| splunk-attack-data-wmic-xsl | splunk/attack_data | eac2f8f… | Apache-2.0 | unlabeled_requires_review | disabled, unverified |

- Recorded `sha256` values are **Git LFS object ids** from the pointer files at the pinned
  revision (verified 2026-10-13), not hashes of downloaded content.
- **The Sysmon adapter is unverified against a live sample** (no data was downloaded). It is
  unit-tested against a small inline Sysmon XML fixture. To verify end-to-end, the user must
  `git lfs pull --include=...` one enabled file and run `copley data adapt`.
- Default: **no raw-data redistribution.**

## Splits

Train / validation / calibration / test are group-disjoint (see `docs/data-plan.md`). Model
params and vectorizers fit on train only; calibration on calibration only; thresholds chosen on
validation; test untouched until evaluation. Insufficient independent groups/classes yields a
visible `insufficient_data` result, not a random split.

## Known risks

- **Source/label correlation:** if benign and malicious ever come from disjoint sources, the
  result may be a source classifier. Audit acquisition differences and removable lab artifacts;
  if only unmatched sources exist, label the experiment exploratory and block strong claims.
- **Tiny sample:** fixture metrics have no statistical meaning.
