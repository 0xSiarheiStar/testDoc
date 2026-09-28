#Requires -Version 5.0
<#
.SYNOPSIS
    Local credential and sensitive data search for assumed breach assessments.
.DESCRIPTION
    Searches the local machine for stored credentials, SSH keys, browser data,
    config files, Office documents, cloud credentials, and more. Runs as the
    current user; detects elevation for expanded search surface.
.PARAMETER Collectors
    Comma-separated collectors. Default: all.
    Available: history, ssh, git, cloud, browser, credman, wifi, registry,
               apps, stickynotes, configfiles, documents, envvars, windows, tasks
.PARAMETER MaxFileSize
    Max file size (bytes) for content search. Default: 1MB.
.PARAMETER ExtraPaths
    Additional directories to search for config files and documents.
.PARAMETER OutFile
    Save report to file.
.PARAMETER NoColor
    Disable colored output (for piping/redirection).
.EXAMPLE
    .\snaffler_local.ps1
    .\snaffler_local.ps1 -Collectors history,ssh,cloud
    .\snaffler_local.ps1 -OutFile findings.txt -NoColor
#>
param(
    [string]$Collectors = 'all',
    [int]$MaxFileSize = 1048576,
    [string[]]$ExtraPaths = @(),
    [string]$OutFile,
    [switch]$NoColor
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

Add-Type -AssemblyName System.IO.Compression.FileSystem 2>$null

# === Globals ===

$script:IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$script:Findings = [System.Collections.Generic.List[PSObject]]::new()
$script:CurrentUser = $env:USERNAME
$script:UserProfile = $env:USERPROFILE
$script:AppData = $env:APPDATA
$script:LocalAppData = $env:LOCALAPPDATA

# === Output helpers ===

function Write-Banner {
    $banner = @"

  ============================================================================
  ||  snaffler_local - Local Credential & Sensitive Data Hunt             ||
  ============================================================================

"@
    Write-Host $banner -ForegroundColor Cyan
    Write-Host "  User      : $script:CurrentUser" -ForegroundColor Gray
    Write-Host "  Profile   : $script:UserProfile" -ForegroundColor Gray
    Write-Host "  Elevated  : $script:IsAdmin" -ForegroundColor $(if ($script:IsAdmin) { 'Green' } else { 'Yellow' })
    Write-Host "  Date      : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host ""
}

function Add-Finding {
    param(
        [ValidateSet('Red','Yellow','Green')]
        [string]$Severity,
        [string]$Category,
        [string]$Description,
        [string]$Path = '',
        [string]$Detail = '',
        [string]$HighlightPattern = ''
    )
    $f = [PSCustomObject]@{
        Severity    = $Severity
        Category    = $Category
        Description = $Description
        Path        = $Path
        Detail      = if ($Detail.Length -gt 500) { $Detail.Substring(0, 500) + '...' } else { $Detail }
    }
    $script:Findings.Add($f)

    $color = switch ($Severity) { 'Red' { 'Red' } 'Yellow' { 'Yellow' } 'Green' { 'DarkGreen' } }
    $tag = "[$($Severity.ToUpper().PadRight(6))]"
    if ($NoColor) {
        Write-Host "  $tag [$Category] $Description"
    } else {
        Write-Host "  $tag " -ForegroundColor $color -NoNewline
        Write-Host "[$Category] " -ForegroundColor White -NoNewline
        Write-Host $Description -ForegroundColor Gray
    }
    if ($Path) {
        Write-Host "           $Path" -ForegroundColor DarkGray
    }
    if ($Detail) {
        $preview = if ($Detail.Length -gt 200) { $Detail.Substring(0, 200) + '...' } else { $Detail }
        foreach ($line in $preview -split "`n" | Select-Object -First 3) {
            $trimmed = $line.Trim()
            if (-not $NoColor -and $HighlightPattern -and $trimmed -match $HighlightPattern) {
                Write-Host "           > " -ForegroundColor DarkGray -NoNewline
                $parts = $trimmed -split "($HighlightPattern)"
                foreach ($part in $parts) {
                    if ($part -match $HighlightPattern) {
                        Write-Host $part -ForegroundColor Red -NoNewline
                    } else {
                        Write-Host $part -ForegroundColor DarkGray -NoNewline
                    }
                }
                Write-Host ""
            } else {
                Write-Host "           > $trimmed" -ForegroundColor DarkGray
            }
        }
    }
}

function Write-Section {
    param([string]$Name)
    Write-Host ""
    Write-Host "  == $Name ==" -ForegroundColor Cyan
}

# === Content search patterns (ported from snaffler creds-extract.js) ===

$script:ContentPatterns = @(
    @{ Name = 'password';           Regex = '(?i)(?:passw(?:or)?d|pwd|passwd)\s*[=:]\s*["\x27]([^\s"\x27;&<>]{8,})["\x27]' }
    @{ Name = 'password-xml';       Regex = '(?i)(?:passw(?:or)?d|pwd)>\s*([^\s<]{8,})\s*<' }
    @{ Name = 'api-key';            Regex = '(?i)(?:api[_\-]?key|apikey)\s*[=:]\s*["\x27]?([^\s"\x27;&<>]{12,})' }
    @{ Name = 'aws-access-key';     Regex = '(AKIA[0-9A-Z]{16})' }
    @{ Name = 'aws-secret-key';     Regex = '(?i)aws[_\-.]?secret[_\-.]?access[_\-.]?key\s*[=:]\s*["\x27]?([A-Za-z0-9/+=]{40})["\x27]?' }
    @{ Name = 'private-key';        Regex = '-----BEGIN\s+(?:RSA\s+|OPENSSH\s+|DSA\s+|EC\s+|PGP\s+)?PRIVATE KEY' }
    @{ Name = 'connection-string';  Regex = '(?i)(?:Password|Pwd)\s*=\s*([^;"\s]{8,})' }
    @{ Name = 'connection-uri';     Regex = '(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|rediss?|amqp)://(?:[^\s:@/]+):(?:[^\s:@/]{6,})@' }
    @{ Name = 'github-token';       Regex = '(ghp_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{82}|gh[ousr]_[0-9A-Za-z]{36})' }
    @{ Name = 'gitlab-token';       Regex = '(glpat-[0-9A-Za-z_\-]{20})' }
    @{ Name = 'slack-token';        Regex = '(xox[baprs]-[0-9A-Za-z\-]{25,})' }
    @{ Name = 'slack-webhook';      Regex = '(https://hooks\.slack\.com/services/T[A-Za-z0-9_]{8,}/B[A-Za-z0-9_]{8,}/[A-Za-z0-9_]{24,})' }
    @{ Name = 'azure-storage-key';  Regex = 'AccountKey=([A-Za-z0-9+/]{86}==)' }
    @{ Name = 'jwt';                Regex = '(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{20,})' }
    @{ Name = 'bearer-token';       Regex = '(?i)Authorization:\s*Bearer\s+([A-Za-z0-9._\-]{30,})' }
    @{ Name = 'client-secret';      Regex = '(?i)(?:client[_\-]?secret)\s*[=:]\s*["\x27]([^\s"\x27;&<>]{12,})["\x27]' }
    @{ Name = 'secure-string';      Regex = '(?i)ConvertTo-SecureString\s+["\x27]([^\s"\x27|]{12,})["\x27]' }
    @{ Name = 'gpp-cpassword';      Regex = '(?i)cpassword\s*=\s*["\x27]?([A-Za-z0-9+/=]{20,})' }
    @{ Name = 'net-use';            Regex = '(?i)net\s+use\s+\S+\s+/user:(\S+)\s+(\S+)' }
    @{ Name = 'openai-key';         Regex = '(sk-(?:proj-)?[0-9A-Za-z_\-]{40,})' }
    @{ Name = 'stripe-key';         Regex = '([sr]k_live_[0-9A-Za-z]{24,})' }
    @{ Name = 'sendgrid-key';       Regex = '(SG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43})' }
    @{ Name = 'npm-token';          Regex = '(npm_[0-9A-Za-z]{36})' }
    @{ Name = 'gcp-key';            Regex = '(?i)"private_key"\s*:\s*"(-----BEGIN)' }
    @{ Name = 'ansible-vault';      Regex = '(\$ANSIBLE_VAULT;[0-9]\.[0-9];AES256)' }
    @{ Name = 'unattend-password';  Regex = '(?i)<(?:Password|AdministratorPassword)>([^<]{8,})</(?:Password|AdministratorPassword)>' }
)

function Search-ContentString {
    param([string]$Text, [string]$Source)
    foreach ($p in $script:ContentPatterns) {
        if ($Text -match $p.Regex) {
            $matchLine = ($Text -split "`n" | Where-Object { $_ -match $p.Regex } | Select-Object -First 1)
            if ($matchLine) { $matchLine = $matchLine.Trim() }
            $sev = if ($p.Name -match 'password|secret|private-key|cpassword|connection-string|connection-uri') { 'Red' } else { 'Yellow' }
            Add-Finding -Severity $sev -Category "content:$($p.Name)" `
                -Description "Pattern '$($p.Name)' matched in file" `
                -Path $Source -Detail $matchLine -HighlightPattern $p.Regex
        }
    }
}

# === Office document text extraction ===

function Get-OfficeText {
    param([string]$FilePath)
    $text = [System.Text.StringBuilder]::new()
    try {
        $zip = [System.IO.Compression.ZipFile]::OpenRead($FilePath)
        try {
            foreach ($entry in $zip.Entries) {
                $target = $false
                $ext = [System.IO.Path]::GetExtension($FilePath).ToLower()
                if ($ext -eq '.docx' -and $entry.FullName -eq 'word/document.xml') { $target = $true }
                if ($ext -eq '.docx' -and $entry.FullName -like 'word/header*.xml') { $target = $true }
                if ($ext -eq '.docx' -and $entry.FullName -like 'word/footer*.xml') { $target = $true }
                if ($ext -eq '.xlsx' -and $entry.FullName -eq 'xl/sharedStrings.xml') { $target = $true }
                if ($ext -eq '.xlsx' -and $entry.FullName -like 'xl/worksheets/sheet*.xml') { $target = $true }
                if ($ext -eq '.pptx' -and $entry.FullName -like 'ppt/slides/slide*.xml') { $target = $true }
                if ($ext -eq '.pptx' -and $entry.FullName -like 'ppt/notesSlides/notesSlide*.xml') { $target = $true }
                if (-not $target) { continue }
                $stream = $entry.Open()
                try {
                    $reader = [System.IO.StreamReader]::new($stream)
                    $xml = $reader.ReadToEnd()
                    $stripped = $xml -replace '<[^>]+>', ' '
                    $stripped = [System.Net.WebUtility]::HtmlDecode($stripped)
                    [void]$text.AppendLine($stripped)
                } finally { $stream.Dispose() }
            }
        } finally { $zip.Dispose() }
    } catch { }
    return $text.ToString()
}

# === Collectors ===

function Collect-History {
    Write-Section "PowerShell & CMD History"

    $psHistoryPath = Join-Path $script:AppData 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
    if (Test-Path $psHistoryPath) {
        $size = (Get-Item $psHistoryPath).Length
        Add-Finding -Severity Yellow -Category 'history' `
            -Description "PowerShell history found ($([math]::Round($size/1KB, 1)) KB)" `
            -Path $psHistoryPath
        $content = Get-Content $psHistoryPath -Raw
        if ($content) {
            $sensitive = $content -split "`n" | Where-Object {
                $_ -match '(?i)(passw\s*=|password\s*=|secret\s*=|apikey.*=|-password\s|ConvertTo-SecureString|net\s+use\s+\S+\s+\S+\s+\/user|cmdkey\s+\/add|runas\s+\/user|psexec\s+.*-p\s|Invoke-Command.*-Credential|dsquery.*-p\s)' -and
                $_ -notmatch '(?i)(-ClientID|-RedirectUrl|-TenantId|-DisablePKCE|-DisableCAE)'
            } | Select-Object -First 10
            foreach ($line in $sensitive) {
                Add-Finding -Severity Red -Category 'history' `
                    -Description 'Sensitive command in PS history' `
                    -Path $psHistoryPath -Detail $line.Trim() `
                    -HighlightPattern '(?i)(passw\s*=\s*\S+|password\s*=\s*\S+|secret\s*=\s*\S+|apikey.*=\s*\S+|-password\s+\S+|ConvertTo-SecureString.*|net\s+use\s+\S+\s+\S+|/user:\S+|cmdkey.*|runas.*|psexec.*|Invoke-Command.*)'
            }
        }
    }

    if ($script:IsAdmin) {
        Get-ChildItem 'C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt' -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -notlike "*\$script:CurrentUser\*" } |
            ForEach-Object {
                $otherUser = $_.FullName -replace '.*\\Users\\([^\\]+)\\.*','$1'
                Add-Finding -Severity Yellow -Category 'history' `
                    -Description "PS history for other user ($otherUser)" `
                    -Path $_.FullName
                $c = Get-Content $_.FullName -Raw
                if ($c) {
                    $c -split "`n" | Where-Object {
                        $_ -match '(?i)(passw\s*=|password\s*=|secret\s*=|-password\s|ConvertTo-SecureString|net\s+use\s+\S+\s+\S+\s+\/user|cmdkey\s+\/add)' -and
                        $_ -notmatch '(?i)(-ClientID|-RedirectUrl|-TenantId)'
                    } | Select-Object -First 5 | ForEach-Object {
                        Add-Finding -Severity Red -Category 'history' `
                            -Description 'Sensitive command in other user PS history' `
                            -Path $_.FullName -Detail $_.Trim() `
                            -HighlightPattern '(?i)(passw\s*=\s*\S+|password\s*=\s*\S+|secret\s*=\s*\S+|-password\s+\S+|ConvertTo-SecureString.*|net\s+use\s+\S+\s+\S+|/user:\S+|cmdkey.*)'
                    }
                }
            }
    }
}

function Collect-SSH {
    Write-Section "SSH Keys & Config"

    $sshDir = Join-Path $script:UserProfile '.ssh'
    if (Test-Path $sshDir) {
        Get-ChildItem $sshDir -File -ErrorAction SilentlyContinue | ForEach-Object {
            $content = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
            if ($content -match '-----BEGIN\s+(RSA|OPENSSH|DSA|EC|PGP)\s+PRIVATE KEY') {
                $encrypted = $content -match 'ENCRYPTED'
                $sev = if ($encrypted) { 'Yellow' } else { 'Red' }
                $desc = if ($encrypted) { "SSH private key (encrypted)" } else { "SSH private key (UNENCRYPTED)" }
                Add-Finding -Severity $sev -Category 'ssh' -Description $desc -Path $_.FullName
            } elseif ($_.Name -eq 'config') {
                Add-Finding -Severity Green -Category 'ssh' `
                    -Description 'SSH config (may contain hostnames, jump hosts, key paths)' `
                    -Path $_.FullName
                if ($content) { Search-ContentString $content $_.FullName }
            } elseif ($_.Name -eq 'known_hosts') {
                $count = ($content -split "`n").Count
                Add-Finding -Severity Green -Category 'ssh' `
                    -Description "SSH known_hosts ($count entries - reveals infrastructure)" `
                    -Path $_.FullName
            } elseif ($_.Name -eq 'authorized_keys') {
                Add-Finding -Severity Yellow -Category 'ssh' `
                    -Description 'authorized_keys - shows who can SSH in' `
                    -Path $_.FullName
            }
        }
    }

    if ($script:IsAdmin) {
        Get-ChildItem 'C:\Users\*\.ssh\id_*' -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -notlike "*\$script:CurrentUser\*" } |
            ForEach-Object {
                $c = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
                if ($c -match 'PRIVATE KEY') {
                    $enc = $c -match 'ENCRYPTED'
                    $keyOwner = $_.FullName -replace '.*\\Users\\([^\\]+)\\.*','$1'
                    $encLabel = if ($enc) { '(encrypted)' } else { '(UNENCRYPTED)' }
                    $keySev = if ($enc) { 'Yellow' } else { 'Red' }
                    Add-Finding -Severity $keySev -Category 'ssh' `
                        -Description "SSH key for $keyOwner $encLabel" `
                        -Path $_.FullName
                }
            }
    }
}

function Collect-Git {
    Write-Section "Git Credentials"

    $gitCred = Join-Path $script:UserProfile '.git-credentials'
    if (Test-Path $gitCred) {
        Add-Finding -Severity Red -Category 'git' `
            -Description 'Git credential store - plaintext URLs with passwords' `
            -Path $gitCred
        $content = Get-Content $gitCred -Raw
        if ($content) {
            $content -split "`n" | Where-Object { $_.Trim() } | Select-Object -First 5 | ForEach-Object {
                $sanitized = $_ -replace '://([^:]+):([^@]+)@', '://${1}:***@'
                Add-Finding -Severity Red -Category 'git' `
                    -Description 'Stored git credential' -Detail $sanitized.Trim()
            }
        }
    }

    $gitConfig = Join-Path $script:UserProfile '.gitconfig'
    if (Test-Path $gitConfig) {
        $content = Get-Content $gitConfig -Raw
        if ($content -match '(?i)(token|password|secret|credential)') {
            Add-Finding -Severity Yellow -Category 'git' `
                -Description 'gitconfig may contain credentials' `
                -Path $gitConfig
            Search-ContentString $content $gitConfig
        }
    }

    # credential manager git entries
    $credManGit = Join-Path $script:LocalAppData 'Microsoft\Git Credential Manager'
    if (Test-Path $credManGit) {
        Add-Finding -Severity Yellow -Category 'git' `
            -Description 'Git Credential Manager storage found' `
            -Path $credManGit
    }
}

function Collect-Cloud {
    Write-Section "Cloud Credentials (AWS / Azure / GCP)"

    # AWS
    $awsCreds = Join-Path $script:UserProfile '.aws\credentials'
    if (Test-Path $awsCreds) {
        Add-Finding -Severity Red -Category 'cloud:aws' `
            -Description 'AWS credentials file' -Path $awsCreds
        $content = Get-Content $awsCreds -Raw
        if ($content -match '(AKIA|ASIA)') {
            Add-Finding -Severity Red -Category 'cloud:aws' `
                -Description 'AWS access key found in credentials' -Path $awsCreds
        }
    }
    $awsConfig = Join-Path $script:UserProfile '.aws\config'
    if (Test-Path $awsConfig) {
        Add-Finding -Severity Green -Category 'cloud:aws' `
            -Description 'AWS config (profiles, regions, role ARNs)' -Path $awsConfig
    }

    # Azure
    $azureDir = Join-Path $script:UserProfile '.azure'
    if (Test-Path $azureDir) {
        $tokenFiles = @('accessTokens.json', 'msal_token_cache.json', 'azureProfile.json', 'msal_token_cache.bin')
        foreach ($tf in $tokenFiles) {
            $tp = Join-Path $azureDir $tf
            if (Test-Path $tp) {
                Add-Finding -Severity Red -Category 'cloud:azure' `
                    -Description "Azure token/profile: $tf" -Path $tp
            }
        }
    }
    # Az PowerShell token cache
    $azPsCache = Join-Path $script:UserProfile '.Azure\TokenCache.dat'
    if (Test-Path $azPsCache) {
        Add-Finding -Severity Red -Category 'cloud:azure' `
            -Description 'Azure PowerShell token cache' -Path $azPsCache
    }

    # GCP
    $gcpCreds = Join-Path $script:AppData 'gcloud\credentials.db'
    if (Test-Path $gcpCreds) {
        Add-Finding -Severity Red -Category 'cloud:gcp' `
            -Description 'GCP credentials database' -Path $gcpCreds
    }
    $gcpAdc = Join-Path $script:AppData 'gcloud\application_default_credentials.json'
    if (Test-Path $gcpAdc) {
        Add-Finding -Severity Red -Category 'cloud:gcp' `
            -Description 'GCP application default credentials' -Path $gcpAdc
    }
    $gcpLegacy = Join-Path $script:AppData 'gcloud\legacy_credentials'
    if (Test-Path $gcpLegacy) {
        Add-Finding -Severity Red -Category 'cloud:gcp' `
            -Description 'GCP legacy credentials directory' -Path $gcpLegacy
    }

    # Kubernetes
    $kubeConfig = Join-Path $script:UserProfile '.kube\config'
    if (Test-Path $kubeConfig) {
        $content = Get-Content $kubeConfig -Raw
        $sev = if ($content -match '(?i)(client-key-data|token|password)') { 'Red' } else { 'Yellow' }
        Add-Finding -Severity $sev -Category 'cloud:k8s' `
            -Description 'Kubernetes config with cluster credentials' -Path $kubeConfig
    }

    # Docker
    $dockerConfig = Join-Path $script:UserProfile '.docker\config.json'
    if (Test-Path $dockerConfig) {
        $content = Get-Content $dockerConfig -Raw
        if ($content -match '"auth"') {
            Add-Finding -Severity Red -Category 'cloud:docker' `
                -Description 'Docker config with registry auth (base64 user:pass)' -Path $dockerConfig
        }
    }
}

function Collect-Browser {
    Write-Section "Browser Data"

    $browsers = @(
        @{ Name = 'Chrome';       Base = Join-Path $script:LocalAppData 'Google\Chrome\User Data' }
        @{ Name = 'Edge';         Base = Join-Path $script:LocalAppData 'Microsoft\Edge\User Data' }
        @{ Name = 'Brave';        Base = Join-Path $script:LocalAppData 'BraveSoftware\Brave-Browser\User Data' }
        @{ Name = 'Vivaldi';      Base = Join-Path $script:LocalAppData 'Vivaldi\User Data' }
        @{ Name = 'Opera';        Base = Join-Path $script:AppData 'Opera Software\Opera Stable' }
    )

    foreach ($b in $browsers) {
        if (-not (Test-Path $b.Base)) { continue }

        $profiles = @('Default') + @(Get-ChildItem $b.Base -Directory -Filter 'Profile *' -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })

        foreach ($prof in $profiles) {
            $profDir = Join-Path $b.Base $prof
            if (-not (Test-Path $profDir)) { continue }

            $loginData = Join-Path $profDir 'Login Data'
            if (Test-Path $loginData) {
                Add-Finding -Severity Red -Category 'browser' `
                    -Description "$($b.Name) stored passwords (DPAPI encrypted SQLite)" `
                    -Path $loginData
            }

            $cookies = Join-Path $profDir 'Cookies'
            if (-not (Test-Path $cookies)) { $cookies = Join-Path $profDir 'Network\Cookies' }
            if (Test-Path $cookies) {
                Add-Finding -Severity Yellow -Category 'browser' `
                    -Description "$($b.Name) cookies (session tokens, auth cookies)" `
                    -Path $cookies
            }

            $localState = Join-Path $b.Base 'Local State'
            if (Test-Path $localState) {
                $ls = Get-Content $localState -Raw
                if ($ls -match '"encrypted_key"') {
                    Add-Finding -Severity Red -Category 'browser' `
                        -Description "$($b.Name) DPAPI master key for cookie/password decryption" `
                        -Path $localState
                }
            }

            $bookmarks = Join-Path $profDir 'Bookmarks'
            if (Test-Path $bookmarks) {
                $bk = Get-Content $bookmarks -Raw
                if ($bk -match '(?i)(password|admin|vpn|jenkins|gitlab|jira|confluence|grafana|kibana)') {
                    Add-Finding -Severity Green -Category 'browser' `
                        -Description "$($b.Name) bookmarks contain interesting URLs" `
                        -Path $bookmarks
                }
            }
        }
    }

    # Firefox
    $ffBase = Join-Path $script:AppData 'Mozilla\Firefox\Profiles'
    if (Test-Path $ffBase) {
        Get-ChildItem $ffBase -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $loginsJson = Join-Path $_.FullName 'logins.json'
            $key4 = Join-Path $_.FullName 'key4.db'
            if (Test-Path $loginsJson) {
                Add-Finding -Severity Red -Category 'browser' `
                    -Description 'Firefox stored passwords (logins.json)' `
                    -Path $loginsJson
            }
            if (Test-Path $key4) {
                Add-Finding -Severity Red -Category 'browser' `
                    -Description 'Firefox key database (needed to decrypt logins)' `
                    -Path $key4
            }
            $cookies = Join-Path $_.FullName 'cookies.sqlite'
            if (Test-Path $cookies) {
                Add-Finding -Severity Yellow -Category 'browser' `
                    -Description 'Firefox cookies' -Path $cookies
            }
        }
    }
}

function Collect-CredentialManager {
    Write-Section "Windows Credential Manager"

    $output = cmdkey /list 2>$null
    if ($output) {
        $entries = @($output | Select-String 'Target:' | ForEach-Object { $_.Line.Trim() })
        if ($entries.Count -gt 0) {
            Add-Finding -Severity Yellow -Category 'credman' `
                -Description "Credential Manager has $($entries.Count) stored credential(s)"
            foreach ($entry in $entries | Select-Object -First 15) {
                $target = ($entry -replace '.*Target:\s*', '').Trim()
                $sev = if ($target -match '(?i)(TERMSRV|Domain|MicrosoftOffice|WindowsLive|virtualapp)') { 'Yellow' } else { 'Green' }
                if ($target -match '(?i)(git|azure|aws|ssh|vpn|rdp|smb|ftp|sql|admin)') { $sev = 'Yellow' }
                Add-Finding -Severity $sev -Category 'credman' `
                    -Description "Stored credential: $target"
            }
        }
    }

    # DPAPI credential blobs
    $dpapiCreds = Join-Path $script:AppData 'Microsoft\Credentials'
    if (Test-Path $dpapiCreds) {
        $count = @(Get-ChildItem $dpapiCreds -File -ErrorAction SilentlyContinue).Count
        if ($count -gt 0) {
            Add-Finding -Severity Yellow -Category 'credman' `
                -Description "DPAPI credential blobs ($count files - decryptable with master key)" `
                -Path $dpapiCreds
        }
    }
    $dpapiCredsLocal = Join-Path $script:LocalAppData 'Microsoft\Credentials'
    if (Test-Path $dpapiCredsLocal) {
        $count = @(Get-ChildItem $dpapiCredsLocal -File -ErrorAction SilentlyContinue).Count
        if ($count -gt 0) {
            Add-Finding -Severity Yellow -Category 'credman' `
                -Description "DPAPI credential blobs local ($count files)" `
                -Path $dpapiCredsLocal
        }
    }
}

function Collect-WiFi {
    Write-Section "WiFi Profiles"

    $profiles = netsh wlan show profiles 2>$null
    if (-not $profiles) { return }

    $names = @($profiles | Select-String 'All User Profile\s*:\s*(.+)' | ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() })
    if ($names.Count -eq 0) { return }

    foreach ($name in $names) {
        $detail = netsh wlan show profile name="$name" key=clear 2>$null
        $keyLine = $detail | Select-String 'Key Content\s*:\s*(.+)'
        if ($keyLine) {
            $key = $keyLine.Matches[0].Groups[1].Value.Trim()
            Add-Finding -Severity Red -Category 'wifi' `
                -Description "WiFi password for '$name'" -Detail "Key: $key"
        } else {
            $authLine = $detail | Select-String 'Authentication\s*:\s*(.+)'
            $auth = if ($authLine) { $authLine.Matches[0].Groups[1].Value.Trim() } else { 'unknown' }
            if ($auth -ne 'Open') {
                Add-Finding -Severity Yellow -Category 'wifi' `
                    -Description "WiFi profile '$name' ($auth) - password not readable (need elevation)"
            }
        }
    }
}

function Collect-Registry {
    Write-Section "Registry Secrets"

    # AutoLogon
    $wlPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $defaultPw = try { (Get-ItemProperty $wlPath -ErrorAction Stop).DefaultPassword } catch { $null }
    $defaultUser = try { (Get-ItemProperty $wlPath -ErrorAction Stop).DefaultUserName } catch { $null }
    $defaultDomain = try { (Get-ItemProperty $wlPath -ErrorAction Stop).DefaultDomainName } catch { $null }
    if ($defaultPw) {
        Add-Finding -Severity Red -Category 'registry' `
            -Description "AutoLogon password for $defaultDomain\$defaultUser" `
            -Path $wlPath -Detail "DefaultPassword = $defaultPw"
    } elseif ($defaultUser) {
        Add-Finding -Severity Green -Category 'registry' `
            -Description "AutoLogon configured for $defaultDomain\$defaultUser (no stored password)" `
            -Path $wlPath
    }

    # PuTTY sessions
    $puttyPath = 'HKCU:\Software\SimonTatham\PuTTY\Sessions'
    if (Test-Path $puttyPath) {
        $sessions = Get-ChildItem $puttyPath -ErrorAction SilentlyContinue
        foreach ($s in $sessions) {
            $host = (Get-ItemProperty $s.PSPath -Name HostName -ErrorAction SilentlyContinue).HostName
            $user = (Get-ItemProperty $s.PSPath -Name UserName -ErrorAction SilentlyContinue).UserName
            $proxy = (Get-ItemProperty $s.PSPath -Name ProxyPassword -ErrorAction SilentlyContinue).ProxyPassword
            $ppkFile = (Get-ItemProperty $s.PSPath -Name PublicKeyFile -ErrorAction SilentlyContinue).PublicKeyFile

            $desc = "PuTTY session '$($s.PSChildName)'"
            if ($host) { $desc += " -> $host" }
            if ($user) { $desc += " (user: $user)" }
            $sev = 'Green'
            $detail = ''
            if ($proxy) { $sev = 'Red'; $detail = "ProxyPassword = $proxy" }
            if ($ppkFile -and (Test-Path $ppkFile)) { $sev = 'Yellow'; $detail = "Key: $ppkFile" }

            Add-Finding -Severity $sev -Category 'registry' `
                -Description $desc -Path $s.PSPath -Detail $detail
        }
    }

    # WinSCP
    $winscpPath = 'HKCU:\Software\Martin Prikryl\WinSCP 2\Sessions'
    if (Test-Path $winscpPath) {
        $sessions = Get-ChildItem $winscpPath -ErrorAction SilentlyContinue
        foreach ($s in $sessions) {
            $host = (Get-ItemProperty $s.PSPath -Name HostName -ErrorAction SilentlyContinue).HostName
            $user = (Get-ItemProperty $s.PSPath -Name UserName -ErrorAction SilentlyContinue).UserName
            $pass = (Get-ItemProperty $s.PSPath -Name Password -ErrorAction SilentlyContinue).Password
            if (-not $host) { continue }
            $sev = if ($pass) { 'Red' } else { 'Yellow' }
            $detail = if ($pass) { "Encrypted password stored (WinSCP obfuscation is reversible)" } else { '' }
            Add-Finding -Severity $sev -Category 'registry' `
                -Description "WinSCP session: $user@$host" -Path $s.PSPath -Detail $detail
        }
    }

    # VNC
    $vncPaths = @(
        'HKCU:\Software\RealVNC\vncserver', 'HKCU:\Software\TightVNC\Server',
        'HKLM:\Software\RealVNC\vncserver', 'HKLM:\Software\TightVNC\Server',
        'HKCU:\Software\ORL\WinVNC3', 'HKLM:\Software\ORL\WinVNC3'
    )
    foreach ($vp in $vncPaths) {
        if (-not (Test-Path $vp)) { continue }
        $pass = (Get-ItemProperty $vp -Name Password -ErrorAction SilentlyContinue).Password
        if ($pass) {
            Add-Finding -Severity Red -Category 'registry' `
                -Description "VNC password stored (DES-encrypted, trivially reversible)" `
                -Path $vp
        }
    }

    # SNMP
    $snmpPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities'
    if (Test-Path $snmpPath) {
        Add-Finding -Severity Yellow -Category 'registry' `
            -Description 'SNMP community strings in registry' -Path $snmpPath
    }
}

function Collect-Apps {
    Write-Section "Application Credentials"

    # FileZilla
    $fzSiteMgr = Join-Path $script:AppData 'FileZilla\sitemanager.xml'
    if (Test-Path $fzSiteMgr) {
        $content = Get-Content $fzSiteMgr -Raw
        $sev = if ($content -match '<Pass') { 'Red' } else { 'Yellow' }
        Add-Finding -Severity $sev -Category 'apps' `
            -Description 'FileZilla Site Manager (may contain stored passwords)' `
            -Path $fzSiteMgr
    }
    $fzRecent = Join-Path $script:AppData 'FileZilla\recentservers.xml'
    if (Test-Path $fzRecent) {
        $content = Get-Content $fzRecent -Raw
        if ($content -match '<Pass') {
            Add-Finding -Severity Red -Category 'apps' `
                -Description 'FileZilla recent servers with stored passwords' `
                -Path $fzRecent
        }
    }

    # mRemoteNG
    $mremote = Join-Path $script:AppData 'mRemoteNG\confCons.xml'
    if (Test-Path $mremote) {
        Add-Finding -Severity Red -Category 'apps' `
            -Description 'mRemoteNG connections (AES-GCM encrypted - default key is public)' `
            -Path $mremote
    }

    # KeePass
    $keepassConfig = @(
        (Join-Path $script:AppData 'KeePass\KeePass.config.xml'),
        (Join-Path $script:LocalAppData 'KeePass\KeePass.config.xml')
    )
    foreach ($kc in $keepassConfig) {
        if (Test-Path $kc) {
            $content = Get-Content $kc -Raw
            $dbPaths = [regex]::Matches($content, '<Path>(.+?\.kdbx)</Path>')
            Add-Finding -Severity Yellow -Category 'apps' `
                -Description 'KeePass config - reveals database paths' -Path $kc
            foreach ($m in $dbPaths) {
                $dbPath = $m.Groups[1].Value
                if (Test-Path $dbPath) {
                    Add-Finding -Severity Yellow -Category 'apps' `
                        -Description 'KeePass database file found' -Path $dbPath
                }
            }
        }
    }
    # Search for .kdbx files in common locations
    $kdbxSearch = @($script:UserProfile, 'C:\Users\Public', "$script:UserProfile\Documents", "$script:UserProfile\Desktop")
    foreach ($sp in $kdbxSearch) {
        if (-not (Test-Path $sp)) { continue }
        Get-ChildItem $sp -Recurse -Filter '*.kdbx' -Depth 3 -ErrorAction SilentlyContinue | ForEach-Object {
            Add-Finding -Severity Yellow -Category 'apps' `
                -Description "KeePass database" -Path $_.FullName
        }
    }

    # RDP files with passwords
    $rdpSearch = @("$script:UserProfile\Documents", "$script:UserProfile\Desktop", "$script:UserProfile\Downloads")
    foreach ($sp in $rdpSearch) {
        if (-not (Test-Path $sp)) { continue }
        Get-ChildItem $sp -Filter '*.rdp' -Depth 2 -ErrorAction SilentlyContinue | ForEach-Object {
            $content = Get-Content $_.FullName -Raw
            $sev = if ($content -match '(?i)password 51:') { 'Red' } else { 'Green' }
            $server = if ($content -match 'full address:s:(.+)') { $Matches[1].Trim() } else { 'unknown' }
            Add-Finding -Severity $sev -Category 'apps' `
                -Description "RDP shortcut to $server$(if($sev -eq 'Red'){' (has stored password)'})" `
                -Path $_.FullName
        }
    }

    # Remmina (WSL)
    $remmina = Join-Path $script:LocalAppData 'Packages\*\LocalState\rootfs\home\*\.local\share\remmina'
    Get-ChildItem $remmina -Filter '*.remmina' -ErrorAction SilentlyContinue | ForEach-Object {
        Add-Finding -Severity Yellow -Category 'apps' `
            -Description 'Remmina connection file (WSL)' -Path $_.FullName
    }

    # HeidiSQL
    $heidi = 'HKCU:\Software\HeidiSQL\Servers'
    if (Test-Path $heidi) {
        Get-ChildItem $heidi -ErrorAction SilentlyContinue | ForEach-Object {
            $pass = (Get-ItemProperty $_.PSPath -Name Password -ErrorAction SilentlyContinue).Password
            if ($pass) {
                Add-Finding -Severity Red -Category 'apps' `
                    -Description "HeidiSQL stored password for $($_.PSChildName)" -Path $_.PSPath
            }
        }
    }

    # DBeaver
    $dbeaver = Join-Path $script:AppData 'DBeaverData\workspace6\General\.dbeaver\credentials-config.json'
    if (Test-Path $dbeaver) {
        Add-Finding -Severity Red -Category 'apps' `
            -Description 'DBeaver credentials store' -Path $dbeaver
    }
}

function Collect-StickyNotes {
    Write-Section "Sticky Notes"

    $stickyPaths = @(
        (Join-Path $script:LocalAppData 'Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite'),
        (Join-Path $script:LocalAppData 'Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite-wal')
    )
    foreach ($sp in $stickyPaths) {
        if (Test-Path $sp) {
            $size = (Get-Item $sp).Length
            if ($size -gt 0) {
                $sizeKB = [math]::Round($size/1KB, 1)
                Add-Finding -Severity Yellow -Category 'stickynotes' `
                    -Description "Sticky Notes database ($sizeKB KB) - people store passwords here" `
                    -Path $sp
            }
        }
    }
}

function Collect-ConfigFiles {
    Write-Section "Config Files (content grep)"

    $extensions = @('*.config', '*.xml', '*.json', '*.yaml', '*.yml', '*.env', '*.ini',
                    '*.conf', '*.cfg', '*.properties', '*.toml', '*.ps1', '*.bat',
                    '*.cmd', '*.vbs', '*.py', '*.rb', '*.tf', '*.tfvars')
    $searchDirs = @(
        $script:UserProfile,
        "$script:UserProfile\Documents",
        "$script:UserProfile\Desktop",
        "$script:UserProfile\Downloads",
        "$script:UserProfile\source",
        'C:\inetpub',
        'C:\Scripts',
        'C:\Temp',
        'C:\Users\Public'
    ) + $ExtraPaths

    if ($script:IsAdmin) {
        $searchDirs += @(
            'C:\Windows\System32\inetsrv\config',
            'C:\Windows\Panther',
            'C:\Windows\sysprep'
        )
    }

    $scanned = 0
    $maxScan = 2000

    foreach ($dir in $searchDirs) {
        if (-not (Test-Path $dir)) { continue }
        foreach ($ext in $extensions) {
            Get-ChildItem $dir -Recurse -Filter $ext -Depth 5 -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Length -gt 0 -and $_.Length -lt $MaxFileSize } |
                ForEach-Object {
                    if ($scanned -ge $maxScan) { return }
                    $scanned++
                    try {
                        $content = Get-Content $_.FullName -Raw -ErrorAction Stop
                        if ($content) { Search-ContentString $content $_.FullName }
                    } catch { }
                }
        }
    }
    Write-Host "           Scanned $scanned config files" -ForegroundColor DarkGray
}

function Collect-Documents {
    Write-Section "Office Documents (content grep)"

    $extensions = @('*.docx', '*.xlsx', '*.pptx')
    $searchDirs = @(
        "$script:UserProfile\Documents",
        "$script:UserProfile\Desktop",
        "$script:UserProfile\Downloads",
        'C:\Users\Public\Documents'
    )
    if ($script:IsAdmin) {
        Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notin @('Public', $script:CurrentUser, 'Default', 'Default User', 'All Users') } |
            ForEach-Object { $searchDirs += "$($_.FullName)\Documents"; $searchDirs += "$($_.FullName)\Desktop" }
    }

    $scanned = 0
    $maxScan = 500

    foreach ($dir in $searchDirs) {
        if (-not (Test-Path $dir)) { continue }
        foreach ($ext in $extensions) {
            Get-ChildItem $dir -Recurse -Filter $ext -Depth 4 -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Length -gt 0 -and $_.Length -lt ($MaxFileSize * 5) } |
                ForEach-Object {
                    if ($scanned -ge $maxScan) { return }
                    $scanned++
                    try {
                        $text = Get-OfficeText $_.FullName
                        if ($text) { Search-ContentString $text $_.FullName }
                    } catch { }
                }
        }
    }

    # Also search plain text files in the same locations
    $textExts = @('*.txt', '*.csv', '*.log', '*.md')
    foreach ($dir in $searchDirs) {
        if (-not (Test-Path $dir)) { continue }
        foreach ($ext in $textExts) {
            Get-ChildItem $dir -Recurse -Filter $ext -Depth 4 -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Length -gt 0 -and $_.Length -lt $MaxFileSize } |
                ForEach-Object {
                    if ($scanned -ge $maxScan) { return }
                    $scanned++
                    try {
                        $content = Get-Content $_.FullName -Raw -ErrorAction Stop
                        if ($content) { Search-ContentString $content $_.FullName }
                    } catch { }
                }
        }
    }

    # Flag PDFs (can't parse but worth noting)
    foreach ($dir in $searchDirs) {
        if (-not (Test-Path $dir)) { continue }
        $pdfCount = @(Get-ChildItem $dir -Recurse -Filter '*.pdf' -Depth 3 -File -ErrorAction SilentlyContinue).Count
        if ($pdfCount -gt 0) {
            Add-Finding -Severity Green -Category 'documents' `
                -Description "$pdfCount PDF files in $dir (cannot parse - manual review needed)" `
                -Path $dir
        }
    }

    Write-Host "           Scanned $scanned documents" -ForegroundColor DarkGray
}

function Collect-EnvVars {
    Write-Section "Environment Variables"

    $env = Get-ChildItem env: | Where-Object {
        $_.Name -imatch '^(.*PASSWORD|.*SECRET|.*TOKEN|.*KEY|DB_CONN|CONN_STRING|DB_.*|API_.*|GITHUB_.*|AWS_.*|AZURE_.*|GCP_.*|STRIPE_.*|SENDGRID_.*|SLACK_.*|MONGO_.*|POSTGRES_.*|MYSQL_.*)$' -and
        $_.Value.Length -gt 8
    }

    $excluded = @('PATH','PATHEXT','PROGRAMFILES','SYSTEMROOT','WINDIR','TEMP','TMP','HOMEDRIVE','HOMEPATH','COMPUTERNAME')
    foreach ($e in $env) {
        if ($e.Name -in $excluded) { continue }
        $sev = if ($e.Value -match '(?i)(password|secret|://.*:.*@|^[A-Za-z0-9]{20,}$)' -and $e.Value.Length -gt 12) { 'Red' } else { 'Yellow' }
        Add-Finding -Severity $sev -Category 'envvars' `
            -Description "env:$($e.Name)" -Detail $e.Value `
            -HighlightPattern '(?i)[A-Za-z0-9._\-+/]{16,}|(?:password|secret).*|://.*:.*@'
    }
}

function Collect-Windows {
    Write-Section "Windows Secrets (admin-only checks included)"

    # Unattend/Sysprep
    $unattendPaths = @(
        'C:\Windows\Panther\unattend.xml',
        'C:\Windows\Panther\Unattend\unattend.xml',
        'C:\Windows\Panther\unattended.xml',
        'C:\Windows\System32\sysprep\unattend.xml',
        'C:\Windows\System32\sysprep\Panther\unattend.xml',
        'C:\unattend.xml'
    )
    foreach ($up in $unattendPaths) {
        if (Test-Path $up) {
            $content = Get-Content $up -Raw
            $sev = if ($content -match '(?i)<(Password|AdministratorPassword)') { 'Red' } else { 'Yellow' }
            Add-Finding -Severity $sev -Category 'windows' `
                -Description "Unattend/sysprep file$(if($sev -eq 'Red'){' with password'})" `
                -Path $up
            if ($content) { Search-ContentString $content $up }
        }
    }

    # SAM/SYSTEM backup copies
    if ($script:IsAdmin) {
        $regBackups = @(
            'C:\Windows\repair\SAM', 'C:\Windows\repair\SYSTEM', 'C:\Windows\repair\SECURITY',
            'C:\Windows\System32\config\RegBack\SAM', 'C:\Windows\System32\config\RegBack\SYSTEM',
            'C:\Windows\System32\config\RegBack\SECURITY'
        )
        foreach ($rb in $regBackups) {
            if (Test-Path $rb) {
                $size = (Get-Item $rb).Length
                if ($size -gt 0) {
                    $hiveName = [System.IO.Path]::GetFileName($rb)
                    Add-Finding -Severity Red -Category 'windows' `
                        -Description "Registry hive backup ($hiveName) - extractable hashes" `
                        -Path $rb
                }
            }
        }

        # DPAPI master keys for all users
        Get-ChildItem 'C:\Users\*\AppData\Roaming\Microsoft\Protect\S-*' -ErrorAction SilentlyContinue |
            ForEach-Object {
                $keyCount = @(Get-ChildItem $_.FullName -File -ErrorAction SilentlyContinue).Count
                if ($keyCount -gt 0) {
                    $user = $_.FullName -replace '.*\\Users\\([^\\]+)\\.*', '$1'
                    Add-Finding -Severity Yellow -Category 'windows' `
                        -Description "DPAPI master keys for $user ($keyCount keys)" `
                        -Path $_.FullName
                }
            }

        # IIS applicationHost.config
        $iisConfig = 'C:\Windows\System32\inetsrv\config\applicationHost.config'
        if (Test-Path $iisConfig) {
            $content = Get-Content $iisConfig -Raw
            if ($content -match '(?i)<(Password|identityPassword)>([^<]{8,})</') {
                Add-Finding -Severity Red -Category 'windows' `
                    -Description 'IIS config contains plaintext credentials' `
                    -Path $iisConfig
                Search-ContentString $content $iisConfig
            }
        }

        # Shadow copies
        $vss = vssadmin list shadows 2>$null
        if ($vss -match 'Shadow Copy Volume') {
            $count = @($vss | Select-String 'Shadow Copy ID').Count
            Add-Finding -Severity Yellow -Category 'windows' `
                -Description "Volume Shadow Copies exist ($count) - may contain old SAM/NTDS" `
                -Detail 'Access via: mklink /d C:\shadow \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\'
        }
    }

    # Scheduled tasks with credentials (works as user, limited view)
    $tasksDir = 'C:\Windows\System32\Tasks'
    if (Test-Path $tasksDir) {
        Get-ChildItem $tasksDir -Recurse -File -Depth 3 -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $content = Get-Content $_.FullName -Raw -ErrorAction Stop
                if ($content -match '(?i)<Password>([^<]+)</Password>') {
                    Add-Finding -Severity Red -Category 'windows' `
                        -Description "Scheduled task with stored password" `
                        -Path $_.FullName
                }
                if ($content -match '(?i)<UserId>([^<]+)</UserId>') {
                    $userId = $Matches[1]
                    if ($userId -match '\\' -and $content -match '(?i)S4U|Password|InteractiveToken') {
                        Add-Finding -Severity Yellow -Category 'windows' `
                            -Description "Scheduled task runs as $userId" -Path $_.FullName
                    }
                }
            } catch { }
        }
    }
}

function Collect-Tasks {
    Write-Section "Interesting Scheduled Tasks"

    try {
        $tasks = schtasks /query /fo CSV /v 2>$null | ConvertFrom-Csv -ErrorAction Stop
        $tasks | Where-Object {
            $_.'Run As User' -and
            $_.'Run As User' -notmatch '(?i)(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|N/A|Authenticated Users|Users|Everyone)' -and
            $_.'Task To Run' -notmatch '(?i)(COM handler|SystemRoot|Windows\\system32)'
        } | Select-Object -First 20 | ForEach-Object {
            Add-Finding -Severity Yellow -Category 'tasks' `
                -Description "Task '$($_.'TaskName')' runs as $($_.'Run As User')" `
                -Detail $_.'Task To Run'
        }
    } catch { }
}

# === Report ===

function Write-Report {
    Write-Host ""
    Write-Host "  == Summary ==" -ForegroundColor Cyan

    $red = @($script:Findings | Where-Object { $_.Severity -eq 'Red' }).Count
    $yellow = @($script:Findings | Where-Object { $_.Severity -eq 'Yellow' }).Count
    $green = @($script:Findings | Where-Object { $_.Severity -eq 'Green' }).Count

    Write-Host ""
    Write-Host "    RED    : $red" -ForegroundColor Red
    Write-Host "    YELLOW : $yellow" -ForegroundColor Yellow
    Write-Host "    GREEN  : $green" -ForegroundColor DarkGreen
    Write-Host "    TOTAL  : $($script:Findings.Count)" -ForegroundColor White
    Write-Host ""

    # Auto-save to file (unless suppressed via -NoColor which can indicate piping)
    $reportFile = if ($OutFile) { $OutFile } else { "snaffler_findings_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt" }

    $report = [System.Text.StringBuilder]::new()
    $reportDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    [void]$report.AppendLine("snaffler_local report - $reportDate")
    [void]$report.AppendLine("User: $script:CurrentUser | Elevated: $script:IsAdmin")
    [void]$report.AppendLine("=" * 80)
    [void]$report.AppendLine("")

    foreach ($sev in @('Red', 'Yellow', 'Green')) {
        $items = @($script:Findings | Where-Object { $_.Severity -eq $sev })
        if ($items.Count -eq 0) { continue }
        [void]$report.AppendLine("[$($sev.ToUpper())] - $($items.Count) findings")
        [void]$report.AppendLine("-" * 40)
        foreach ($f in $items) {
            [void]$report.AppendLine("  [$($f.Category)] $($f.Description)")
            if ($f.Path) { [void]$report.AppendLine("    Path: $($f.Path)") }
            if ($f.Detail) { [void]$report.AppendLine("    Detail: $($f.Detail)") }
        }
        [void]$report.AppendLine("")
    }

    $report.ToString() | Out-File -FilePath $reportFile -Encoding utf8
    Write-Host "  Report saved to: $reportFile" -ForegroundColor Green

    # Also generate HTML report
    $htmlFile = $reportFile -replace '\.txt$', '.html'
    $html = Generate-HTMLReport
    $html | Out-File -FilePath $htmlFile -Encoding utf8
    Write-Host "  HTML report:    $htmlFile" -ForegroundColor Green
}

function Generate-HTMLReport {
    $red = @($script:Findings | Where-Object { $_.Severity -eq 'Red' }).Count
    $yellow = @($script:Findings | Where-Object { $_.Severity -eq 'Yellow' }).Count
    $green = @($script:Findings | Where-Object { $_.Severity -eq 'Green' }).Count
    $reportDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>snaffler_local Report</title>
    <style>
        :root {
            --primary: #2563eb;
            --primary-dark: #1e40af;
            --primary-light: #3b82f6;
            --bg-dark: #0f172a;
            --bg-darker: #020617;
            --bg-card: #1e293b;
            --bg-hover: #334155;
            --text-primary: #f1f5f9;
            --text-secondary: #cbd5e1;
            --border: #334155;
            --critical: #ef4444;
            --warning: #f59e0b;
            --success: #10b981;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif;
            background: var(--bg-darker);
            color: var(--text-primary);
            line-height: 1.6;
        }

        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }

        header {
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
            color: white;
            padding: 40px;
            border-radius: 12px;
            margin-bottom: 30px;
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5);
            display: flex;
            align-items: center;
            gap: 30px;
        }

        .logo-section { flex-shrink: 0; }
        .logo { width: 80px; height: 80px; background: rgba(255,255,255,0.1); border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 36px; font-weight: bold; border: 2px solid rgba(255,255,255,0.2); }
        .header-content { flex: 1; }
        h1 { font-size: 28px; margin-bottom: 8px; }
        .header-info { font-size: 13px; opacity: 0.9; margin-bottom: 5px; }

        .summary { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 30px; }
        .stat-card {
            background: var(--bg-card);
            padding: 24px;
            border-radius: 10px;
            border: 1px solid var(--border);
            transition: all 0.3s ease;
        }
        .stat-card:hover {
            border-color: var(--primary-light);
            transform: translateY(-2px);
            box-shadow: 0 10px 15px -3px rgba(37, 99, 235, 0.2);
        }

        .stat-card h2 { font-size: 36px; margin: 12px 0; font-weight: 700; }
        .stat-card p { font-size: 13px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.5px; }

        .stat-red h2 { color: var(--critical); }
        .stat-yellow h2 { color: var(--warning); }
        .stat-green h2 { color: var(--success); }
        .stat-total h2 { color: var(--primary-light); }

        .controls {
            background: var(--bg-card);
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            border: 1px solid var(--border);
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }

        .controls input, .controls select {
            padding: 10px 14px;
            background: var(--bg-dark);
            color: var(--text-primary);
            border: 1px solid var(--border);
            border-radius: 6px;
            font-size: 13px;
            transition: all 0.2s ease;
        }

        .controls input:focus, .controls select:focus {
            outline: none;
            border-color: var(--primary-light);
            box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1);
        }

        .controls button {
            padding: 10px 20px;
            background: var(--primary);
            color: white;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 13px;
            font-weight: 600;
            transition: all 0.2s ease;
        }

        .controls button:hover {
            background: var(--primary-dark);
            transform: translateY(-1px);
            box-shadow: 0 4px 6px -1px rgba(37, 99, 235, 0.3);
        }

        .findings {
            background: var(--bg-card);
            border-radius: 10px;
            border: 1px solid var(--border);
            overflow: hidden;
        }

        .finding {
            border-bottom: 1px solid var(--border);
            padding: 20px;
            transition: background 0.2s ease;
        }

        .finding:hover { background: var(--bg-hover); }
        .finding:last-child { border-bottom: none; }
        .finding.hidden { display: none; }

        .severity {
            display: inline-block;
            padding: 6px 12px;
            border-radius: 6px;
            font-weight: 600;
            font-size: 11px;
            margin-right: 10px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .severity-red { background: rgba(239, 68, 68, 0.2); color: var(--critical); border: 1px solid rgba(239, 68, 68, 0.3); }
        .severity-yellow { background: rgba(245, 158, 11, 0.2); color: var(--warning); border: 1px solid rgba(245, 158, 11, 0.3); }
        .severity-green { background: rgba(16, 185, 129, 0.2); color: var(--success); border: 1px solid rgba(16, 185, 129, 0.3); }

        .category {
            display: inline-block;
            background: rgba(37, 99, 235, 0.2);
            color: var(--primary-light);
            padding: 4px 10px;
            border-radius: 5px;
            font-size: 11px;
            border: 1px solid rgba(37, 99, 235, 0.3);
        }

        .description {
            font-size: 14px;
            font-weight: 600;
            margin: 12px 0 8px 0;
            color: var(--text-primary);
        }

        .path {
            font-family: 'Courier New', monospace;
            background: var(--bg-dark);
            padding: 10px 14px;
            border-left: 3px solid var(--primary-light);
            margin: 10px 0;
            font-size: 12px;
            color: var(--text-secondary);
            word-break: break-all;
            border-radius: 4px;
        }

        .detail {
            background: var(--bg-dark);
            padding: 12px;
            border-radius: 6px;
            font-family: 'Courier New', monospace;
            font-size: 11px;
            color: var(--text-secondary);
            margin: 10px 0;
            max-height: 200px;
            overflow-y: auto;
            word-break: break-all;
            border: 1px solid var(--border);
        }

        .detail::-webkit-scrollbar { width: 6px; }
        .detail::-webkit-scrollbar-track { background: transparent; }
        .detail::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }

        .footer {
            text-align: center;
            margin-top: 40px;
            color: var(--text-secondary);
            font-size: 12px;
            padding: 20px;
            border-top: 1px solid var(--border);
        }

        @media (max-width: 1024px) { .summary { grid-template-columns: repeat(2, 1fr); } header { flex-direction: column; text-align: center; } }
        @media (max-width: 768px) { .summary { grid-template-columns: 1fr; } header h1 { font-size: 22px; } .controls { flex-direction: column; } .controls input, .controls select, .controls button { width: 100%; } }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo-section">
                <div class="logo">🔐</div>
            </div>
            <div class="header-content">
                <h1>snaffler_local</h1>
                <div class="header-info">Credential & Sensitive Data Audit Report</div>
                <div class="header-info">User: $script:CurrentUser | Elevated: $script:IsAdmin | $reportDate</div>
            </div>
        </header>

        <div class="summary">
            <div class="stat-card stat-red">
                <p>Critical</p>
                <h2>$red</h2>
            </div>
            <div class="stat-card stat-yellow">
                <p>Warning</p>
                <h2>$yellow</h2>
            </div>
            <div class="stat-card stat-green">
                <p>Info</p>
                <h2>$green</h2>
            </div>
            <div class="stat-card stat-total">
                <p>Total</p>
                <h2>$($script:Findings.Count)</h2>
            </div>
        </div>

        <div class="controls">
            <input type="text" id="searchInput" placeholder="Search findings..." onkeyup="filterFindings()">
            <select id="severityFilter" onchange="filterFindings()">
                <option value="">All Severities</option>
                <option value="red">Critical Only</option>
                <option value="yellow">Warnings Only</option>
                <option value="green">Info Only</option>
            </select>
            <select id="categoryFilter" onchange="filterFindings()">
                <option value="">All Categories</option>
"@

    $categories = $script:Findings | Select-Object -ExpandProperty Category -Unique | Sort-Object
    foreach ($cat in $categories) {
        $html += "                <option value=""$cat"">$cat</option>`n"
    }

    $html += @"
            </select>
            <button onclick="resetFilters()">Reset Filters</button>
        </div>

        <div class="findings">
"@

    foreach ($f in $script:Findings) {
        $sevClass = "severity-$($f.Severity.ToLower())"
        $dataAttrs = "data-severity=""$($f.Severity.ToLower())"" data-category=""$($f.Category)"""
        $html += @"
            <div class="finding" $dataAttrs>
                <div style="margin-bottom: 8px;">
                    <span class="severity $sevClass">$($f.Severity.ToUpper())</span>
                    <span class="category">$($f.Category)</span>
                </div>
                <div class="description">$($f.Description)</div>
"@
        if ($f.Path) {
            $encodedPath = [System.Web.HttpUtility]::HtmlEncode($f.Path)
            $html += "                <div class=""path"">[Path] $encodedPath</div>`n"
        }
        if ($f.Detail) {
            $encodedDetail = [System.Web.HttpUtility]::HtmlEncode($f.Detail)
            $html += "                <div class=""detail"">$encodedDetail</div>`n"
        }
        $html += "            </div>`n"
    }

    $html += @"
        </div>

        <div class="footer">
            <p>snaffler_local - Local Credential & Sensitive Data Hunt</p>
            <p>Generated: $reportDate</p>
        </div>
    </div>

    <script>
        function filterFindings() {
            const searchTerm = document.getElementById('searchInput').value.toLowerCase();
            const severityFilter = document.getElementById('severityFilter').value;
            const categoryFilter = document.getElementById('categoryFilter').value;
            const findings = document.querySelectorAll('.finding');

            findings.forEach(finding => {
                const matches = (!severityFilter || finding.dataset.severity === severityFilter) &&
                               (!categoryFilter || finding.dataset.category === categoryFilter) &&
                               (finding.textContent.toLowerCase().includes(searchTerm));
                finding.classList.toggle('hidden', !matches);
            });
        }

        function resetFilters() {
            document.getElementById('searchInput').value = '';
            document.getElementById('severityFilter').value = '';
            document.getElementById('categoryFilter').value = '';
            filterFindings();
        }
    </script>
</body>
</html>
"@
    return $html
}

# === Main ===

$allCollectors = @{
    history     = { Collect-History }
    ssh         = { Collect-SSH }
    git         = { Collect-Git }
    cloud       = { Collect-Cloud }
    browser     = { Collect-Browser }
    credman     = { Collect-CredentialManager }
    wifi        = { Collect-WiFi }
    registry    = { Collect-Registry }
    apps        = { Collect-Apps }
    stickynotes = { Collect-StickyNotes }
    configfiles = { Collect-ConfigFiles }
    documents   = { Collect-Documents }
    envvars     = { Collect-EnvVars }
    windows     = { Collect-Windows }
    tasks       = { Collect-Tasks }
}

$runOrder = @('history','ssh','git','cloud','browser','credman','wifi',
              'registry','apps','stickynotes','envvars','windows','tasks',
              'configfiles','documents')

Write-Banner

$selected = if ($Collectors -eq 'all') { $runOrder } else { $Collectors -split ',' | ForEach-Object { $_.Trim().ToLower() } }

foreach ($name in $selected) {
    if ($allCollectors.ContainsKey($name)) {
        try {
            & $allCollectors[$name]
        } catch {
            Write-Host "  [!] Collector '$name' failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "  [!] Unknown collector: $name" -ForegroundColor Red
    }
}

Write-Report