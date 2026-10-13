"""Rule manifest hash verification."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from copley.rules.manifest import RuleManifestError, default_manifest_path, load_rule_manifest


def test_manifest_loads_and_verifies():
    entries = load_rule_manifest(default_manifest_path())
    assert len(entries) == 8
    licenses = {e.license for e in entries}
    assert "Apache-2.0" in licenses  # local rules
    assert any(lic.startswith("DRL") for lic in licenses)  # sigmahq rules


def test_tampered_rule_detected(tmp_path: Path):
    manifest = default_manifest_path()
    data = yaml.safe_load(manifest.read_text())
    # Point one entry at a tampered copy by corrupting the recorded hash.
    data["rules"][0]["sha256"] = "0" * 64
    out = tmp_path / "rules.yaml"
    out.write_text(yaml.safe_dump(data), encoding="utf-8")
    with pytest.raises(RuleManifestError, match="sha256 mismatch"):
        load_rule_manifest(out)


def test_missing_rule_file_errors(tmp_path: Path):
    data = yaml.safe_load(default_manifest_path().read_text())
    data["rules"] = [{"set": "local", "file": "does_not_exist.yml", "sha256": "0" * 64}]
    out = tmp_path / "rules.yaml"
    out.write_text(yaml.safe_dump(data), encoding="utf-8")
    with pytest.raises(RuleManifestError, match="missing"):
        load_rule_manifest(out)
