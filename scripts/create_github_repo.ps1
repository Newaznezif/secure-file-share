<#
PowerShell script to create a GitHub repository and push the current project.
Usage (PowerShell):
  .\scripts\create_github_repo.ps1 -RepoName secure-file-share -Visibility public -Description "Secure file-share demo" -SetSecrets

Behavior:
- If GitHub CLI (`gh`) is installed and authenticated, uses `gh repo create` to create the repo under the authenticated user and pushes the current branch.
- Otherwise, if `GITHUB_TOKEN` is set in environment, uses GitHub REST API to create the repo and pushes the current branch.
- Optionally sets commonly used secrets (AWS_* env vars) using `gh secret set` (requires gh).

Security: Do NOT hardcode tokens in scripts. Use environment variables or `gh auth login`.
#>
param(
    [string]$RepoName = "secure-file-share",
    [ValidateSet('public','private')]
    [string]$Visibility = 'public',
    [string]$Description = "Secure file-share demo (AES-256, KMS, CI)",
    [switch]$SetSecrets
)

function ExitWith($code, $msg) {
    Write-Error $msg
    exit $code
}

Write-Host "Creating GitHub repo: $RepoName (visibility: $Visibility)"

# Prefer gh if available
$gh = Get-Command gh -ErrorAction SilentlyContinue
if ($gh) {
    Write-Host "Using gh CLI to create repo (ensure you're authenticated with 'gh auth login')."
    # Create repo under current authenticated user
    $createArgs = @($RepoName, "--$Visibility", "--source=.", "--remote=origin", "--push", "--description", $Description)
    $proc = Start-Process -FilePath gh -ArgumentList @('repo','create') + $createArgs -NoNewWindow -Wait -PassThru -RedirectStandardError stderr.txt -RedirectStandardOutput stdout.txt
    if ($proc.ExitCode -ne 0) {
        Get-Content stderr.txt
        ExitWith 1 "gh repo create failed. Ensure you are logged in (gh auth login) and try again."
    }
    Write-Host "Repository created and pushed via gh.";

    if ($SetSecrets) {
        Write-Host "Setting secrets using gh (will read AWS_* and GITHUB_TOKEN if present)."
        $secrets = @('AWS_KMS_KEY_ID','AWS_REGION','AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY')
        foreach ($s in $secrets) {
            $val = (Get-Item -Path Env:$s -ErrorAction SilentlyContinue).Value
            if ($val) {
                Write-Host "Setting secret: $s"
                gh secret set $s --body $val
            }
        }
    }
    exit 0
}

# Fallback to GitHub API if GITHUB_TOKEN is set
$token = (Get-Item -Path Env:GITHUB_TOKEN -ErrorAction SilentlyContinue).Value
if (-not $token) {
    ExitWith 2 "Neither 'gh' CLI available nor GITHUB_TOKEN set. Install gh or set GITHUB_TOKEN environment variable."
}

# Create repo via REST API
$apiBody = @{ name = $RepoName; private = ($Visibility -eq 'private'); description = $Description } | ConvertTo-Json
$headers = @{ Authorization = "token $token"; 'User-Agent' = 'create_github_repo_script' }
try {
    $resp = Invoke-RestMethod -Method Post -Uri https://api.github.com/user/repos -Headers $headers -Body $apiBody
} catch {
    ExitWith 3 "GitHub API create repo failed: $_"
}

$owner = $resp.owner.login
$cloneUrl = $resp.clone_url
Write-Host "Created repo: $owner/$RepoName"
Write-Host "Adding remote origin: $cloneUrl"

# Add remote and push
if (-not (git remote get-url origin -ErrorAction SilentlyContinue)) {
    git remote add origin $cloneUrl
}

git branch -M main
try {
    git push -u origin main
} catch {
    ExitWith 4 "git push failed: $_"
}

if ($SetSecrets) {
    Write-Host "Cannot set secrets via REST in this script. Install gh CLI and run 'gh secret set' manually, or set secrets in repo settings."
}

Write-Host "Done. Repository is available at: $resp.html_url"