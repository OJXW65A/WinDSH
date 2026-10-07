# JSON and RMM reports

[Back to usage](USAGE.md)

WinDSH declares schema version **2.1** separately from its application version.
Full reports use PascalCase fields; the compact `-Rmm` result uses camelCase.
Consumers should check `SchemaVersion` or `schemaVersion`, accept additional fields,
and handle unknown status strings conservatively.

## Control states

| State | Meaning | Scoring |
|---|---|---|
| `Running` | Runtime evidence confirms activity, or a configuration-only control satisfies its registry requirement | Full weight |
| `ConfiguredNotRunning` | Configured locally but not confirmed active | Half weight |
| `NotConfigured` | No acceptable local configuration and no active runtime evidence | Zero |
| `NotSupported` | A platform prerequisite is not met | Excluded |
| `Unknown` | Required platform, runtime, or local configuration evidence is unavailable or invalid | Zero; retained in denominator |
| `AuditMode` | Shadow stacks report audit mode without enforcement | Zero; retained in denominator |

Detection-only controls have zero weight. `RunningKnown` identifies whether the
state evaluator has usable evidence; it does not turn a configuration-only setting
into a runtime measurement. Policy management and CIS compliance remain separate
from runtime state. An unreadable policy produces `PolicyReadError` and blocks
changes to the affected control and its dependencies.

`SupportKnown` distinguishes confirmed support or a confirmed unmet prerequisite
from failed prerequisite queries. `Supported = false` with `SupportKnown = false`
blocks remediation but does not exclude the control from scoring. Known hardware
limits remain `NotSupported`. `Score.ApplicableCount` includes scored unknown
controls retained in the denominator.

## Full JSON (`-JsonReport`)

| Field | Contents |
|---|---|
| `SchemaVersion`, `Tool`, `Generated` | Schema string, tool name/version/integrity result, and UTC assessment timestamp |
| `Computer`, `Firmware`, `Tpm`, `HypervisorLaunch`, `Restart` | Collected platform and boot facts; `Tpm.IsTPM2Known` distinguishes unknown TPM evidence |
| `DeviceGuard` | Availability, runtime service evidence, whether services are known, and query error |
| `Policy` | `Available`, per-value `Values`, and per-value `Errors`; read failures are distinct from absence |
| `Controls` | Catalog statuses including `SupportKnown`, `RunningKnown`, `ConfigurationError`, and `PolicyReadError` |
| `Score` | Score, grade, weights and breakdown; `UnknownCount` counts scored unknown controls |
| `SecuredCore` | Qualification and per-criterion results |
| `Cis` | Policy comparison; each row has `PolicyKnown` and `FeatureRunningKnown`; `UnknownCount` counts unavailable policy checks |
| `AppliedChanges` | Actual registry writes made by apply in this process |
| `RevertedChanges` | Actual rollback writes in this process: `RunId`, `ControlId`, `Path`, `Name`, `Before`, `RestoredTo` |
| `Warnings` | Diagnostic strings |

`RestoredTo` is the previous registry value, or `(removed)` when that value did not
exist before apply. Changes are counted after the registry operation succeeds,
even if writing its journal completion marker subsequently fails. Journal recovery
markers and `-WhatIf` previews are not registry writes.

## Compact JSON (`-Rmm`)

RMM emits exactly one JSON object on stdout. For an assessed run it includes:

| Field | Meaning |
|---|---|
| `schemaVersion`, `tool`, `version`, `computer`, `generated` | Report identity and UTC assessment timestamp |
| `score`, `grade` | Applicable protection score and grade |
| `unknownControls`, `unknownCisChecks` | All unknown control states, including detection-only controls; unavailable CIS checks |
| `controls` | Array of `id`, `state`, `policy`, `policyKnown`, `runningKnown`, `supportKnown` |
| `cisCompliant`, `cisTotal` | Policy-compliant and total mapped checks |
| `firmwareMode`, `secureBoot`, `tpm2`, `hypervisorBlocksVbs` | Collected platform and boot summary |
| `tpm2Known` | Whether TPM version or confirmed absence was available; check before interpreting `tpm2` |
| `changes` | Actual apply plus rollback writes during this process |
| `appliedChangeCount`, `revertedChangeCount` | Separate apply and rollback write counts |
| `restartRequired`, `warnings`, `exitCode` | WinDSH restart flag, warning count, and final process exit code |

If startup, validation, or elevation fails before assessment, the object instead
contains `schemaVersion`, `tool`, `version`, `exitCode`, `restartRequired`, and `error`.
Consumers must handle this smaller error shape. Exit-code meanings are listed in
[usage](USAGE.md#exit-codes-and-restart).

## Changes from schema 2.0

Schema 2.1 adds `Unknown` and `AuditMode` states, evidence and policy availability,
unknown counts, and rollback records/counts. Existing fields remain. The RMM
`changes` total now includes rollback writes; integrations that need only apply
activity should read `appliedChangeCount`. Unavailable evidence can no longer be
interpreted as proof that a protection is running or that policy is absent.
