#requires -Version 7.0
<#
Dedicated Windows provisioning utility, never called by CI or the router.
Private key material stays in memory, a CurrentUser-DPAPI backup, and the
explicitly selected repository Actions secret. No private PEM is written.
DPAPI recovery needs this Windows account/profile; this is not a portable backup.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Inspect', 'Create', 'Upload', 'Verify')][string]$Action,
    [Parameter(Mandatory)][string]$BackupDirectory,
    [Parameter(Mandatory)][string]$PublicKeyPath,
    [string]$GhPath = 'gh'
)

$ErrorActionPreference = 'Stop'
$taskRepository = 'blindtechnique/keen-pbr-sb'
$taskSecretName = 'KEENETIC_RELEASE_SIGNING_KEY'
$taskUtf8 = [Text.UTF8Encoding]::new($false)
$taskBackupRoot = [IO.Path]::GetFullPath($BackupDirectory)
$taskPublicPath = [IO.Path]::GetFullPath($PublicKeyPath)
$taskBackupPath = Join-Path $taskBackupRoot 'keenetic-release-v1.pkcs8.dpapi'
$taskMetadataPath = Join-Path $taskBackupRoot 'metadata.json'

function Invoke-PrivateProcess {
    param([string]$Program, [string[]]$Arguments, [string]$InputText = '', [hashtable]$Environment = @{})
    $taskStart = [Diagnostics.ProcessStartInfo]::new()
    $taskStart.FileName = $Program
    $taskStart.UseShellExecute = $false
    $taskStart.CreateNoWindow = $true
    $taskStart.RedirectStandardInput = $true
    $taskStart.RedirectStandardOutput = $true
    $taskStart.RedirectStandardError = $true
    foreach ($taskArg in $Arguments) { $taskStart.ArgumentList.Add($taskArg) }
    foreach ($taskName in $Environment.Keys) { $taskStart.Environment[$taskName] = $Environment[$taskName] }
    $taskProcess = [Diagnostics.Process]::new()
    $taskProcess.StartInfo = $taskStart
    try {
        [void]$taskProcess.Start()
        $taskOut = $taskProcess.StandardOutput.ReadToEndAsync()
        $taskErr = $taskProcess.StandardError.ReadToEndAsync()
        $taskProcess.StandardInput.Write($InputText)
        $taskProcess.StandardInput.Close()
        if (-not $taskProcess.WaitForExit(60000)) {
            $taskProcess.Kill($true)
            throw 'Credential or GitHub request timed out; no retry was performed.'
        }
        # Never echo subprocess output on failures: it may contain credentials.
        $taskResult = @{ Code = $taskProcess.ExitCode; Output = $taskOut.GetAwaiter().GetResult() }
        [void]$taskErr.GetAwaiter().GetResult()
        return $taskResult
    } finally { $taskProcess.Dispose() }
}

function Get-GitHubEnvironment {
    $taskLogin = Invoke-PrivateProcess $GhPath @('auth', 'status', '--hostname', 'github.com')
    if ($taskLogin.Code -eq 0) { return @{} }
    # Reuse only the normal credential helper for this repository. Do not inspect
    # credential files, other hosts, browser stores, or unrelated environment keys.
    $taskCredential = Invoke-PrivateProcess 'git' @('credential', 'fill') `
        "protocol=https`nhost=github.com`npath=$taskRepository.git`n`n" `
        @{ GIT_TERMINAL_PROMPT = '0'; GCM_INTERACTIVE = 'never' }
    if ($taskCredential.Code -ne 0) { throw 'GitHub login required. Run gh auth login --web, then retry.' }
    $taskTokenLine = $taskCredential.Output -split "`n" | Where-Object { $_.StartsWith('password=') } | Select-Object -First 1
    if (-not $taskTokenLine) { throw 'GitHub login required. No repository credential was returned.' }
    return @{ GH_TOKEN = $taskTokenLine.Substring(9).TrimEnd("`r"); GH_PROMPT_DISABLED = '1' }
}

function Get-RemoteSecret {
    param([hashtable]$Environment)
    $taskList = Invoke-PrivateProcess $GhPath @('secret', 'list', '--repo', $taskRepository, '--app', 'actions', '--json', 'name,updatedAt') '' $Environment
    if ($taskList.Code -ne 0) { throw 'Cannot inspect repository Actions secrets. Check GitHub login and repository admin access.' }
    return @($taskList.Output | ConvertFrom-Json | Where-Object name -EQ $taskSecretName)
}

function Get-PublicPem {
    param([Security.Cryptography.RSA]$Rsa)
    return $Rsa.ExportSubjectPublicKeyInfoPem().Replace("`r`n", "`n") + "`n"
}

if (-not $IsWindows) { throw 'This backup utility requires Windows DPAPI.' }
# Require a backup outside every Git worktree ancestor, not just outside .git/.
$taskAncestor = $taskBackupRoot
while ($taskAncestor) {
    if (Test-Path -LiteralPath (Join-Path $taskAncestor '.git')) { throw 'Backup must be outside Git worktrees.' }
    $taskParent = [IO.Directory]::GetParent($taskAncestor)
    $taskAncestor = if ($taskParent) { $taskParent.FullName } else { $null }
}

if ($Action -eq 'Inspect') {
    $taskAuthEnvironment = Get-GitHubEnvironment
    $taskRemote = @(Get-RemoteSecret $taskAuthEnvironment)
    [pscustomobject]@{
        repository = $taskRepository; secret = $taskSecretName
        remote_secret_exists = ($taskRemote.Count -gt 0)
        encrypted_backup_exists = (Test-Path -LiteralPath $taskBackupPath)
        public_key_exists = (Test-Path -LiteralPath $taskPublicPath)
    } | ConvertTo-Json -Compress
    exit 0
}

if ($Action -eq 'Create') {
    if ((Test-Path -LiteralPath $taskBackupPath) -or (Test-Path -LiteralPath $taskPublicPath) -or
        (Test-Path -LiteralPath $taskMetadataPath)) { throw 'Key or backup already exists; nothing was overwritten.' }
    if (Test-Path -LiteralPath $taskBackupRoot) {
        if (@(Get-ChildItem -LiteralPath $taskBackupRoot -Force).Count -gt 0) {
            throw 'Use an empty, dedicated backup directory.'
        }
    } else { [void][IO.Directory]::CreateDirectory($taskBackupRoot) }
    $taskAcl = [Security.AccessControl.DirectorySecurity]::new()
    $taskAcl.SetAccessRuleProtection($true, $false)
    $taskOwner = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $taskAcl.SetOwner($taskOwner)
    foreach ($taskSid in @($taskOwner, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
        $taskAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($taskSid,
            'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    }
    Set-Acl -LiteralPath $taskBackupRoot -AclObject $taskAcl
    $taskRsa = [Security.Cryptography.RSA]::Create(3072)
    $taskPrivateBytes = $null
    $taskRoundTrip = $null
    try {
        $taskPrivateBytes = $taskRsa.ExportPkcs8PrivateKey()
        $taskProtected = [Security.Cryptography.ProtectedData]::Protect($taskPrivateBytes, $null,
            [Security.Cryptography.DataProtectionScope]::CurrentUser)
        [IO.File]::WriteAllBytes($taskBackupPath, $taskProtected)
        $taskRoundTrip = [Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($taskBackupPath), $null,
            [Security.Cryptography.DataProtectionScope]::CurrentUser)
        if (-not [Security.Cryptography.CryptographicOperations]::FixedTimeEquals($taskPrivateBytes, $taskRoundTrip)) {
            throw 'Encrypted backup round-trip failed; key was not published.'
        }
        $taskPublic = Get-PublicPem $taskRsa
        [IO.File]::WriteAllText($taskPublicPath, $taskPublic, $taskUtf8)
        [IO.File]::WriteAllText((Join-Path $taskBackupRoot 'release-public.pem'), $taskPublic, $taskUtf8)
        $taskFingerprint = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($taskRsa.ExportSubjectPublicKeyInfo())).ToLowerInvariant()
        $taskMetadata = [ordered]@{
            repository = $taskRepository; secret_name = $taskSecretName; algorithm = 'RSA-3072/SHA-256'
            public_spki_sha256 = $taskFingerprint; created_utc = [DateTime]::UtcNow.ToString('o')
            protection = 'Windows DPAPI CurrentUser; recovery requires this Windows user profile'
        } | ConvertTo-Json
        [IO.File]::WriteAllText($taskMetadataPath, $taskMetadata + "`n", $taskUtf8)
        Write-Output "Created key and verified encrypted backup. Public SPKI SHA256: $taskFingerprint"
        Write-Output "Backup: $taskBackupPath"
    } finally {
        if ($taskPrivateBytes) { [Array]::Clear($taskPrivateBytes, 0, $taskPrivateBytes.Length) }
        if ($taskRoundTrip) { [Array]::Clear($taskRoundTrip, 0, $taskRoundTrip.Length) }
        $taskRsa.Dispose()
    }
    exit 0
}

$taskPrivateBytes = $null
$taskRsa = [Security.Cryptography.RSA]::Create()
try {
    $taskPrivateBytes = [Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($taskBackupPath), $null,
        [Security.Cryptography.DataProtectionScope]::CurrentUser)
    $taskConsumed = 0
    $taskRsa.ImportPkcs8PrivateKey($taskPrivateBytes, [ref]$taskConsumed)
    if ($taskConsumed -ne $taskPrivateBytes.Length -or $taskRsa.KeySize -ne 3072 -or
        (Get-PublicPem $taskRsa) -cne [IO.File]::ReadAllText($taskPublicPath).Replace("`r`n", "`n")) {
        throw 'Encrypted backup does not match the production public key.'
    }
    $taskChallenge = [Security.Cryptography.RandomNumberGenerator]::GetBytes(64)
    $taskProof = $taskRsa.SignData($taskChallenge, [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.RSASignaturePadding]::Pkcs1)
    if (-not $taskRsa.VerifyData($taskChallenge, $taskProof, [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.RSASignaturePadding]::Pkcs1)) { throw 'Backup signing self-check failed.' }
    if ($Action -eq 'Verify') { Write-Output 'Encrypted backup restored in memory; public key and signing self-check match.'; exit 0 }
    $taskAuthEnvironment = Get-GitHubEnvironment
    $taskExisting = @(Get-RemoteSecret $taskAuthEnvironment)
    if ($taskExisting.Count -ne 0) { throw 'Actions signing secret already exists; refusing to replace it without separate approval.' }
    $taskPem = "-----BEGIN PRIVATE KEY-----`n" +
        [Convert]::ToBase64String($taskPrivateBytes, [Base64FormattingOptions]::InsertLineBreaks).Replace("`r`n", "`n") +
        "`n-----END PRIVATE KEY-----`n"
    $taskUpload = Invoke-PrivateProcess $GhPath @('secret', 'set', $taskSecretName, '--repo', $taskRepository, '--app', 'actions') $taskPem $taskAuthEnvironment
    $taskPem = $null
    if ($taskUpload.Code -ne 0) { throw 'Actions secret upload failed or outcome is unknown. Inspect metadata before retrying.' }
    $taskRemote = @(Get-RemoteSecret $taskAuthEnvironment)
    if ($taskRemote.Count -ne 1) { throw 'Upload returned success, but secret metadata could not be confirmed.' }
    Write-Output "Created Actions secret $taskSecretName in $taskRepository; metadata confirmed."
} finally {
    if ($taskPrivateBytes) { [Array]::Clear($taskPrivateBytes, 0, $taskPrivateBytes.Length) }
    $taskRsa.Dispose()
}
