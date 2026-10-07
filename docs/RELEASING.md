# Releases and repository maintenance

[Back to the README](../README.md)

## Before tagging

1. Merge the intended changes into `main` and wait for all five CI jobs to pass.
2. Verify that `ToolVersion` in `src/10-core.ps1`, the generated `WinDSH.ps1`, and
   the intended tag agree. Never hand-edit the generated script.
3. Run the build freshness check and self-test:

   ```powershell
   .\build\Build-WinDSH.ps1 -Check
   .\WinDSH.ps1 -SelfTest
   ```

4. Record an interactive Windows check on representative hardware, including
   audit, preview, deliberately selected remediation, restart if required, and
   rollback. Validate firmware/driver/policy behavior relevant to the release.
   CI coverage on a hosted VM does not replace these checks. Follow the
   [validation matrix and test protocol](VALIDATION.md), and attach actual test records.
5. Review the changelog, README version status, supported-version policy, and
   release notes. Date the version being released and describe its actual changes.

## Create the tag

To release from GitHub's website, open **Actions > WinDSH Release > Run workflow**,
select **main**, enable **Create the version tag and a draft release from main**,
and run the workflow. It refuses an existing version tag, verifies and tests the
checked-out commit, builds and attests the assets, then creates the version tag
and draft release. The workflow's tag push does not start a second workflow run.
Leaving this option disabled only stages artifacts for review.

Alternatively, push the tag from a local checkout:

From an up-to-date, clean checkout of `main`, derive the tag from the built script:

```powershell
git switch main
git pull --ff-only
git status --short
$version = [regex]::Match((Get-Content -Raw .\WinDSH.ps1), "ToolVersion\s*=\s*'([^']+)'").Groups[1].Value
$tag = "v$version"
git tag -a $tag -m "WinDSH $tag"
git push origin $tag
```

Run the tag commands only after the checkout and release checks are complete.
Do not move an existing public tag to another commit.

## Review and publish

The [release workflow](https://github.com/OJXW65A/WinDSH/blob/main/.github/workflows/release.yml) verifies the build,
checks the tag/version match, runs Pester, packages files, creates SHA-256 checksums,
and attests the ZIPs and checksum file. A tag push or an explicit manual release
request from `main` opens a **draft** GitHub Release. Neither route publishes it
automatically; review the built assets before publication.

| Asset | Contents |
|---|---|
| `WinDSH.zip` | Only `Run-WinDSH-AsAdmin.bat` and `WinDSH.ps1`, at the archive root |
| `WinDSH-v<version>.zip` | Application, launcher, documentation, and license |
| `SHA256SUMS-WinDSH-v<version>.txt` | SHA-256 hashes for staged files and both ZIPs |

Before publishing the draft, download the workflow-built `WinDSH.zip`, extract it,
confirm that it contains exactly those two files, and check its SHA-256 hash against
the checksum file. Review the provenance and release notes. State the actual signing
status; there is currently no signing certificate or sponsorship.

Do not hand-upload or replace release assets outside the workflow. If a release
build is wrong, correct the source and cut a new version. The final signed payload,
if signing is introduced, must be the payload that is checksummed and attested.

Both tag and manual release routes check for existing releases before building
and again before creating a draft. An existing published release or draft blocks
uploads; API errors also block uploads. Asset overwrite is disabled. A failed run
may be retried if it did not create a release. If it left a draft, review the draft
and workflow artifacts manually before deciding whether to discard that unpublished
draft or cut another version. Never discard or replace a published release's assets.

After publication, verify the release download links and the packaged version on
the release page. The README distinguishes the source version from the latest
published download. Keep documentation for older releases
available through their tags.

## Branches and repository settings

Use descriptive branches such as `fix/...`, `feat/...`, `docs/...`, or `chore/...`.
Delete a completed branch only after confirming that its PR is merged and that it
has no unique commits. Do not rewrite existing public commit history for tidiness.

Enable automatic deletion of merged branches in repository settings. Protect `main`
with pull requests, block force pushes and deletion, and require these existing checks:

- `Workflow files are valid`
- `Built file is current`
- `Windows PowerShell 5.1`
- `PowerShell 7`
- `Live audit smoke test`

Require branches to be up to date. A single-maintainer project should not require an
approval from another reviewer who does not exist. These settings must be enabled in
GitHub; documenting them does not enforce them.

Keep repository topics and the About description accurate. Disable unused Wiki or
Projects features only after checking whether they contain information users rely on.
