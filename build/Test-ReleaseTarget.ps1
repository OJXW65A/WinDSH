# Read-only safeguard used before the workflow creates a release or uploads assets.
[CmdletBinding()]
param([string]$Repository = $env:GITHUB_REPOSITORY, [string]$Tag)

function Test-ReleaseTarget {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')][string]$Repository,
        [Parameter(Mandatory = $true)][ValidatePattern('^v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?$')][string]$Tag
    )
    if ([string]::IsNullOrWhiteSpace($env:GH_TOKEN)) { throw 'An authenticated release check is required to see existing drafts.' }
    $headers = @{
        Authorization = 'Bearer ' + $env:GH_TOKEN
        Accept = 'application/vnd.github+json'
        'X-GitHub-Api-Version' = '2022-11-28'
    }
    # The by-tag endpoint describes published releases. Listing with push access
    # also sees drafts, so retries cannot silently mix an old and a new asset set.
    $page = 1
    do {
        try {
            $response = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repository/releases?per_page=100&page=$page" -Headers $headers -ErrorAction Stop
            $releases = @($response)
        }
        catch { throw 'Could not verify existing releases. Refusing to create a release or upload assets.' }
        foreach ($release in $releases) {
            if ($null -eq $release -or $null -eq $release.PSObject.Properties['tag_name']) {
                throw 'GitHub returned an unexpected release response. Refusing to upload assets.'
            }
            if ($release.tag_name -eq $Tag) {
                if ($release.draft) { throw "A draft already exists for $Tag. Review that draft manually; this workflow will not replace its assets." }
                throw "Release $Tag is already published. Cut a new version; never replace public release assets."
            }
        }
        $page++
    } while ($releases.Count -eq 100)
}

if ($MyInvocation.InvocationName -ne '.') { Test-ReleaseTarget -Repository $Repository -Tag $Tag }
