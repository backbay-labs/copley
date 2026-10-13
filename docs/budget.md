# Budget and reproducibility

The editable budget policy lives in `configs/budget.yaml`.

- **Founder's target:** $500 first version; **ceiling:** $1,000.
- **Authorized for this scaffold task:** **$0**. Paid execution is disabled.
- **Costs actually incurred by this scaffold task: $0.** No rented compute, no paid APIs, no
  downloads of the pretrained backbone.

## Cost estimation policy

Estimate cost **only after a measured small run**, using an explicitly supplied hourly rate and
recorded assumptions. Report GPU time, preprocessing time, storage, optional API usage, and
elapsed wall time **separately**. `configs/budget.yaml` keeps `gpu_hourly_rate_usd: null` on
purpose — no guessed rate. Where no benchmark exists, the dry-run reports `unknown`.

No estimate guarantees final model quality or a provider-side bill cap.

## Guards are not a billing cap

`max_steps` and `max_wall_seconds` bound a local process. **They do not deallocate a rented
GPU.** For any later cloud run, you are responsible for:

- Explicitly terminating the instance/job when training ends or guards trip.
- Deleting or lifecycle-expiring checkpoints and datasets you no longer need.
- Setting provider-side budget alerts/caps; software timeouts do not enforce them.

## Per-run metadata

Each artifact records config-derived fields plus git revision + dirty status, dependency-lock
digest, label mapping, base-model revision (real mode), weights sha256, and train counts
(`ArtifactMetadata` in `src/copley/models/artifact.py`). Training also records elapsed wall
time, steps, final train loss, best validation loss, and the device used.

In addition, each `copley smoke` run writes a **per-run record** (`run_record.json`) via
`provenance.run_record`, capturing: config, seed, git revision + dirty status, lock digest,
order-independent **source and per-split content digests** (`dataset_digest`), artifact
digests, elapsed seconds, and the `exploratory_only` audit verdict. Never commit secrets,
private telemetry, or unreviewed raw datasets (`.gitignore` excludes `data/` and `artifacts/`).
