# Sample report

[Back to the README](../README.md)

The [sample HTML report](samples/WinDSH-sample.html) and
[README preview](../assets/report-preview.png) use entirely synthetic data. They are
illustrations of the output, not audits of a real computer, recommended target scores,
or evidence that physical Windows behavior has been validated.

Download the HTML file using GitHub's **Download raw file** button, then open the saved
file in a browser. It works offline and has no external scripts, fonts, or stylesheets.

The fixture deliberately includes active, configured-but-inactive, and unknown
protections. Unknown evidence keeps the assessment incomplete. The CIS comparison
uses policy evidence separately from local configuration; active local protections
do not automatically imply a passing CIS policy check.

## Regenerate the sample

From a repository checkout, on either supported PowerShell runtime:

```powershell
.\build\Build-ReportSample.ps1
```

No administrator rights are needed. The generator loads declarations without the
application entry point, uses the in-memory registry provider and a synthetic event
provider, and never collects host evidence or invokes remediation. The fixture clock
is fixed for repeatability. Application version, control descriptions, and report layout
come from the current source rather than a hand-written mockup.

After changing the report or fixture, update the preview from the generated HTML.
Capture its top viewport at **1080 by 1280 CSS pixels**, 100% zoom, light color scheme,
and device scale factor 1. The preview must retain the synthetic-data label. Do not use
an unreviewed report from a user's device, and do not alter the captured score or statuses.

These documentation fixtures may be committed. Ordinary audit reports, debug logs,
test output, and release archives must stay out of the repository.
