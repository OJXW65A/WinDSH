WinDSH v1.5.0 - Changes
========================

Major additions
- Added -WhatIf preview and interactive [P] Preview.
- Added stable unattended/RMM exit-code contract.
- Added -RMM compact JSON stdout mode.
- Added JSON SchemaVersion 1.0.
- Added InitialState/FinalState and richer outcomes to reports.
- Added HVCI/Memory Integrity diagnostics from Code Integrity and Device Guard logs.
- Enable All Safe now skips HVCI when recent Event ID 3087 compatibility evidence is present.
- Added VM detection/informational guidance.
- Added visible grayed UNAVAILABLE menu actions with reasons.
- Added -Version and -SelfTest.
- Refactored large system-state collection into focused collectors.
- Added line-ending normalization to accidental-corruption integrity calculation.
- Improved debug logging of provider exceptions.
- Hardened PowerShell 5.1 collection/null handling.
- Renamed helper functions to approved PowerShell verbs where applicable.

Behavior kept intentionally unchanged
- No BitLocker/device-encryption management.
- No rollback/revert yet (deferred to a later release).
- No Authenticode signature yet (planned once code/interface mature).
- Enable All Safe remains deliberately limited.
- Launcher continues automatic Mark of the Web removal for WinDSH.ps1 only.
- Temporary Process-scope RemoteSigned only; no persistent policy change or GPO bypass.
