<#
.SYNOPSIS
    Enterprise-Grade Secret Scanner with Advanced Detection and Remediation
.DESCRIPTION
    Comprehensive secret scanning tool with entropy analysis, git history scanning,
    machine learning-inspired pattern matching, and automated remediation suggestions.
.PARAMETER Directory
    Root directory to scan for secrets
.PARAMETER ConfigFile
    Path to YAML/JSON configuration file with custom patterns and settings
.PARAMETER LogFile
    Output log file path (default: secret-scan-TIMESTAMP.log)
.PARAMETER OutputFormat
    Output format: text, json, csv, html, sarif (default: text)
.PARAMETER ThrottleLimit
    Number of parallel threads (default: 10)
.PARAMETER ShowProgress
    Display real-time progress information
.PARAMETER ExcludeFolders
    Folders to exclude from scanning
.PARAMETER ExcludeFiles
    File patterns to exclude
.PARAMETER ShowSecretValues
    Display actual secret values (DANGEROUS - use only for debugging)
.PARAMETER WhitelistFile
    Path to whitelist file (one pattern per line)
.PARAMETER MinEntropy
    Minimum Shannon entropy for high-entropy secrets (default: 3.5)
.PARAMETER MinSeverity
    Minimum severity level to report: Low, Medium, High, Critical (default: Low)
.PARAMETER MaxFileSizeMB
    Maximum file size to scan in MB (default: 10)
.PARAMETER ScanGitHistory
    Scan git commit history for secrets (WARNING: can be slow)
.PARAMETER ContextLines
    Number of context lines to show around findings (default: 2)
.PARAMETER Interactive
    Enable interactive mode for immediate remediation
.PARAMETER GenerateReport
    Generate comprehensive HTML report with charts
.PARAMETER FailOnCritical
    Exit with code 1 if any Critical findings are detected
.PARAMETER QuietMode
    Suppress all console output except errors
.EXAMPLE
    .\SecretScanner.ps1 -Directory "C:\MyProject" -OutputFormat json
.EXAMPLE
    .\SecretScanner.ps1 -Directory . -ScanGitHistory -MinSeverity High -GenerateReport
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, HelpMessage="Root directory to scan")]
    [ValidateScript({Test-Path $_ -PathType Container})]
    [string]$Directory,
    
    [Parameter(Mandatory=$false)]
    [string]$ConfigFile,
    
    [Parameter(Mandatory=$false)]
    [string]$LogFile = "secret-scan-$(Get-Date -Format 'yyyyMMdd-HHmmss').log",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("text", "json", "csv", "html", "sarif")]
    [string]$OutputFormat = "text",
    
    [Parameter(Mandatory=$false)]
    [ValidateRange(1, 50)]
    [int]$ThrottleLimit = 10,
    
    [Parameter(Mandatory=$false)]
    [switch]$ShowProgress,
    
    [Parameter(Mandatory=$false)]
    [string[]]$ExcludeFolders = @('.git', '.svn', 'node_modules', 'bin', 'obj', '.vs', '.vscode', 'target', 'build', 'dist', 'vendor', '__pycache__', '.idea', 'bower_components', 'jspm_packages', '.next'),
    
    [Parameter(Mandatory=$false)]
    [string[]]$ExcludeFiles = @('*.min.js', '*.min.css', '*.map', '*.dll', '*.exe', '*.zip', '*.tar', '*.gz', '*.jpg', '*.png', '*.gif', '*.pdf', '*.woff*', '*.ttf', '*.eot', '.env'),
    
    [Parameter(Mandatory=$false)]
    [switch]$ShowSecretValues,
    
    [Parameter(Mandatory=$false)]
    [string]$WhitelistFile,
    
    [Parameter(Mandatory=$false)]
    [ValidateRange(0.0, 8.0)]
    [double]$MinEntropy = 3.5,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Low", "Medium", "High", "Critical")]
    [string]$MinSeverity = "Low",
    
    [Parameter(Mandatory=$false)]
    [ValidateRange(1, 1000)]
    [int]$MaxFileSizeMB = 10,
    
    [Parameter(Mandatory=$false)]
    [switch]$ScanGitHistory,
    
    [Parameter(Mandatory=$false)]
    [ValidateRange(0, 10)]
    [int]$ContextLines = 2,
    
    [Parameter(Mandatory=$false)]
    [switch]$Interactive,
    
    [Parameter(Mandatory=$false)]
    [switch]$GenerateReport,
    
    [Parameter(Mandatory=$false)]
    [switch]$FailOnCritical,
    
    [Parameter(Mandatory=$false)]
    [switch]$QuietMode,

    [Parameter(Mandatory=$false)]
    [switch]$UseCache,
    
    [Parameter(Mandatory=$false)]
    [string]$CacheDirectory = ".secret-scanner-cache"
)

# ═══════════════════════════════════════════════════════════════════════════
# PERFORMANCE OPTIMIZATION MODULES
# ═══════════════════════════════════════════════════════════════════════════
# Load performance optimization modules if available
$modulePath = Join-Path $PSScriptRoot "modules"
$performanceModulesLoaded = $false

if (Test-Path $modulePath) {
    try {
        Import-Module (Join-Path $modulePath "ParallelProcessing.psm1") -Force
        Import-Module (Join-Path $modulePath "FileCache.psm1") -Force
        Import-Module (Join-Path $modulePath "MemoryOptimization.psm1") -Force
        $performanceModulesLoaded = $true
        Write-Verbose "Performance optimization modules loaded successfully"
    }
    catch {
        Write-Warning "Failed to load performance modules: $($_.Exception.Message)"
        $performanceModulesLoaded = $false
    }
}
# ═══════════════════════════════════════════════════════════════════════════

#Requires -Version 5.1

# Global script variables
$script:AllFindings = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
$script:ScannedFiles = 0
$script:TotalFiles = 0
$script:StartTime = Get-Date

# Enhanced secret patterns with metadata
$script:SecretPatterns = @{
    'AWS Access Key ID' = @{
        Patterns = @('(?<![A-Z0-9])(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])')
        Severity = 'Critical'
        Description = 'AWS Access Key ID - grants access to AWS resources'
        Remediation = 'Rotate key immediately in AWS IAM. Use AWS Secrets Manager or environment variables.'
        Entropy = $false
        FalsePositiveKeywords = @()
    }
    'AWS Secret Access Key' = @{
        Patterns = @("(?i)aws[_-]?secret[_-]?access[_-]?key[`"\s]*[:=][`"\s]*[`"\']?([A-Za-z0-9/+=]{40})[`"\']?")
        Severity = 'Critical'
        Description = 'AWS Secret Access Key - provides full AWS account access'
        Remediation = 'Rotate immediately in AWS IAM. Enable MFA. Use AWS Secrets Manager.'
        Entropy = $true
        FalsePositiveKeywords = @('example', 'sample', 'test', 'dummy', 'fake', 'placeholder')
    }
    'AWS Session Token' = @{
        Patterns = @("(?i)aws[_-]?session[_-]?token[`"\s]*[:=][`"\s]*[`"\']?([A-Za-z0-9/+=]{100,})[`"\']?")
        Severity = 'High'
        Description = 'AWS temporary session token'
        Remediation = 'Session tokens expire automatically. Verify token is not from production.'
        Entropy = $false
        FalsePositiveKeywords = @()
    }
    'GitHub Personal Access Token' = @{
        Patterns = @('ghp_[a-zA-Z0-9]{36}', 'gho_[a-zA-Z0-9]{36}', 'ghu_[a-zA-Z0-9]{36}', 'ghs_[a-zA-Z0-9]{36}', 'ghr_[a-zA-Z0-9]{36}')
        Severity = 'Critical'
        Description = 'GitHub Personal Access Token - repository and org access'
        Remediation = 'Revoke token at github.com/settings/tokens. Enable SSO. Use GitHub Apps.'
        Entropy = $false
        FalsePositiveKeywords = @()
    }
    'GitHub OAuth Token' = @{
        Patterns = @("(?i)github[_-]?oauth[`"\s]*[:=][`"\s]*[`"\']?([a-f0-9]{40})[`"\']?")
        Severity = 'Critical'
        Description = 'GitHub OAuth access token'
        Remediation = 'Revoke token immediately. Rotate OAuth app credentials.'
        Entropy = $true
        FalsePositiveKeywords = @('sha1', 'hash', 'commit')
    }
    'GitLab Personal Access Token' = @{
        Patterns = @('glpat-[a-zA-Z0-9_-]{20,}')
        Severity = 'Critical'
        Description = 'GitLab Personal Access Token'
        Remediation = 'Revoke token in GitLab settings. Use deploy tokens for CI/CD.'
        Entropy = $false
        FalsePositiveKeywords = @()
    }
    'Generic High-Entropy API Key' = @{
        Patterns = @("(?i)(api[_-]?key|apikey|api[_-]?secret)[`"\s]*[:=][`"\s]*[`"\']([a-zA-Z0-9_\-]{32,})[`"\']?")
        Severity = 'High'
        Description = 'Generic API key with high entropy'
        Remediation = 'Identify service and rotate key. Use secrets management system.'
        Entropy = $true
        FalsePositiveKeywords = @('your', 'example', 'insert', 'placeholder')
    }
    'Private Key (PEM)' = @{
        Patterns = @('-----BEGIN[ A-Z]*PRIVATE KEY-----')
        Severity = 'Critical'
        Description = 'PEM-encoded private key'
        Remediation = 'Remove immediately. Generate new keypair. Never commit private keys.'
        Entropy = $false
        FalsePositiveKeywords = @()
    }
    'RSA Private Key' = @{
        Patterns = @('-----BEGIN RSA PRIVATE KEY-----')
        Severity = 'Critical'
        Description = 'RSA private key'
        Remediation = 'Delete key. Generate new keypair. Use hardware security module for production.'
        Entropy = $false
        FalsePositiveKeywords = @()
    }
    'SSH Private Key' = @{
        Patterns = @('-----BEGIN OPENSSH PRIVATE KEY-----')
        Severity = 'Critical'
        Description = 'OpenSSH private key'
        Remediation = 'Remove key. Generate new SSH keypair with passphrase.'
        Entropy = $false
        FalsePositiveKeywords = @()
    }
    'PGP Private Key' = @{
        Patterns = @('-----BEGIN PGP PRIVATE KEY BLOCK-----')
        Severity = 'Critical'
        Description = 'PGP private key block'
        Remediation = 'Revoke key. Generate new PGP keypair with strong passphrase.'
        Entropy = $false
        FalsePositiveKeywords = @()
    }
    'JWT Token' = @{
        Patterns = @('eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}')
        Severity = 'High'
        Description = 'JSON Web Token - may contain sensitive claims'
        Remediation = 'Verify token expiration. Rotate signing keys if compromised.'
        Entropy = $false
        FalsePositiveKeywords = @()
    }
    'Google API Key' = @{
        Patterns = @('AIza[0-9A-Za-z_-]{35}')
        Severity = 'High'
        Description = 'Google Cloud API key'
        Remediation = 'Delete key in Google Cloud Console. Restrict API key usage by IP/app.'
        Entropy = $false
        FalsePositiveKeywords = @()
    }
    'Google OAuth Client ID' = @{
        Patterns = @('[0-9]+-[0-9A-Za-z_-]{32}\.apps\.googleusercontent\.com')
        Severity = 'High'
        Description = 'Google OAuth client ID'
        Remediation = 'Rotate OAuth credentials in Google Cloud Console.'
        Entropy = $false
        FalsePositiveKeywords = @()
    }
    'Slack Token' = @{
        Patterns = @('xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-z0-9]{32}')
        Severity = 'High'
        Description = 'Slack API token'
        Remediation = 'Revoke token at api.slack.com. Regenerate app credentials.'
        Entropy = $false
        FalsePositiveKeywords = @()
    }
    'Slack Webhook' = @{
        Patterns = @('https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+')
        Severity = 'Medium'
        Description = 'Slack incoming webhook URL'
        Remediation = 'Regenerate webhook URL in Slack app settings.'
        Entropy = $false
        FalsePositiveKeywords = @()
    }
    'Stripe Live API Key' = @{
        Patterns = @('sk_live_[0-9a-zA-Z]{24,}')
        Severity = 'Critical'
        Description = 'Stripe live API key - payment processing access'
        Remediation = 'Roll key immediately in Stripe dashboard. Alert security team.'
        Entropy = $false
        FalsePositiveKeywords = @()
    }
    'Stripe Restricted Key' = @{
        Patterns = @('rk_live_[0-9a-zA-Z]{24,}')
        Severity = 'High'
        Description = 'Stripe restricted API key'
        Remediation = 'Roll key in Stripe dashboard. Review key permissions.'
        Entropy = $false
        FalsePositiveKeywords = @()
    }
    'Stripe Test Key' = @{
        Patterns = @('sk_test_[0-9a-zA-Z]{24,}')
        Severity = 'Low'
        Description = 'Stripe test API key'
        Remediation = 'Roll key as precaution. Test keys should not be in production.'
        Entropy = $false
        FalsePositiveKeywords = @()
    }
    'Square Access Token' = @{
        Patterns = @('sq0atp-[0-9A-Za-z\-_]{22}')
        Severity = 'Critical'
        Description = 'Square payment API token'
        Remediation = 'Revoke token in Square Developer dashboard immediately.'
        Entropy = $false
        FalsePositiveKeywords = @()
    }
    'PayPal/Braintree Access Token' = @{
        Patterns = @('access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}')
        Severity = 'Critical'
        Description = 'PayPal/Braintree production access token'
        Remediation = 'Rotate credentials in PayPal/Braintree dashboard. Alert finance team.'
        Entropy = $false
        FalsePositiveKeywords = @()
    }
    'Twilio API Key' = @{
        Patterns = @('(?<![A-Za-z0-9_])SK[a-z0-9]{32}(?![A-Za-z0-9_])')
        Severity = 'High'
        Description = 'Twilio API key'
        Remediation = 'Delete key in Twilio console. Rotate Account SID if needed.'
        Entropy = $false
        FalsePositiveKeywords = @()
    }
    'Twilio Account SID' = @{
        Patterns = @('(?<![A-Za-z0-9_])AC[a-z0-9]{32}(?![A-Za-z0-9_])')
        Severity = 'Medium'
        Description = 'Twilio Account SID'
        Remediation = 'SID is less sensitive but review associated auth tokens.'
        Entropy = $false
        FalsePositiveKeywords = @()
    }
    'SendGrid API Key' = @{
        Patterns = @('SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}')
        Severity = 'High'
        Description = 'SendGrid API key'
        Remediation = 'Delete key in SendGrid dashboard. Create new with minimal permissions.'
        Entropy = $false
        FalsePositiveKeywords = @()
    }
    'Mailgun API Key' = @{
        Patterns = @('key-[a-zA-Z0-9]{32}')
        Severity = 'High'
        Description = 'Mailgun API key'
        Remediation = 'Regenerate key in Mailgun control panel.'
        Entropy = $false
        FalsePositiveKeywords = @()
    }
    'Mailchimp API Key' = @{
        Patterns = @('[a-f0-9]{32}-us[0-9]{1,2}')
        Severity = 'High'
        Description = 'Mailchimp API key'
        Remediation = 'Regenerate API key in Mailchimp account settings.'
        Entropy = $false
        FalsePositiveKeywords = @('md5')
    }
    'Azure Storage Account Key' = @{
        Patterns = @('DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=([A-Za-z0-9+/=]{88});')
        Severity = 'Critical'
        Description = 'Azure Storage account connection string'
        Remediation = 'Regenerate key in Azure Portal. Use Azure Key Vault.'
        Entropy = $false
        FalsePositiveKeywords = @()
    }
    'Azure SAS Token' = @{
        Patterns = @('(\?|&)sig=[A-Za-z0-9%]+')
        Severity = 'High'
        Description = 'Azure Shared Access Signature token'
        Remediation = 'Regenerate SAS token. Use short expiration times.'
        Entropy = $false
        FalsePositiveKeywords = @()
    }
    'NPM Access Token' = @{
        Patterns = @('npm_[a-zA-Z0-9]{36}')
        Severity = 'High'
        Description = 'NPM authentication token'
        Remediation = 'Revoke token at npmjs.com. Use granular access tokens.'
        Entropy = $false
        FalsePositiveKeywords = @()
    }
    'Docker Registry Auth' = @{
        Patterns = @('(?i)(docker[_-]?password|docker[_-]?token)\s*[:=]\s*["\''](([^"\'']{8,}))["\'']]')
        Severity = 'High'
        Description = 'Docker registry credentials'
        Remediation = 'Rotate registry credentials. Use short-lived tokens.'
        Entropy = $true
        FalsePositiveKeywords = @('example')
    }
    'Heroku API Key' = @{
        Patterns = @('[hH][eE][rR][oO][kK][uU].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}')
        Severity = 'High'
        Description = 'Heroku API key'
        Remediation = 'Regenerate API key in Heroku account settings.'
        Entropy = $false
        FalsePositiveKeywords = @()
    }
    'Generic Password Assignment' = @{
        Patterns = @('(?i)(?:password|passwd|pwd)\s*[:=]\s*["'']([^"'']{8,})["'']')
        Severity = 'Medium'
        Description = 'Generic password in configuration'
        Remediation = 'Move to environment variables or secrets management system.'
        Entropy = $true
        FalsePositiveKeywords = @('your', 'enter', 'type', 'example', 'password123', '12345678', 'changeme')
    }
    'Database Connection String (MongoDB)' = @{
        Patterns = @('mongodb(\+srv)?://[^:]+:([^@]+)@[^/]+')
        Severity = 'Critical'
        Description = 'MongoDB connection string with credentials'
        Remediation = 'Rotate database password. Use connection string from secrets manager.'
        Entropy = $false
        FalsePositiveKeywords = @('username', 'user', 'password')
    }
    'Database Connection String (MySQL)' = @{
        Patterns = @('mysql://[^:]+:([^@]+)@[^/]+')
        Severity = 'Critical'
        Description = 'MySQL connection string with credentials'
        Remediation = 'Rotate database password. Use environment variables.'
        Entropy = $false
        FalsePositiveKeywords = @('username', 'password')
    }
    'Database Connection String (PostgreSQL)' = @{
        Patterns = @('postgresql://[^:]+:([^@]+)@[^/]+')
        Severity = 'Critical'
        Description = 'PostgreSQL connection string with credentials'
        Remediation = 'Rotate database password. Use pg_pass file or secrets manager.'
        Entropy = $false
        FalsePositiveKeywords = @('username', 'password')
    }
    'SQL Server Connection String' = @{
        Patterns = @('Server=[^;]+;Database=[^;]+;User Id=[^;]+;Password=([^;]+);')
        Severity = 'Critical'
        Description = 'SQL Server connection string with password'
        Remediation = 'Rotate password. Use Windows Authentication or Azure AD.'
        Entropy = $false
        FalsePositiveKeywords = @()
    }
    'Generic Secret' = @{
        Patterns = @("(?i)(secret|token|credential)[`"\s]*[:=][`"\s]*[`"\']([a-zA-Z0-9_\-\.]{20,})[`"\']?")
        Severity = 'Medium'
        Description = 'Generic secret or token'
        Remediation = 'Identify the service and rotate credentials.'
        Entropy = $true
        FalsePositiveKeywords = @('your', 'example', 'insert')
    }
    'Bearer Token' = @{
        Patterns = @('(?i)bearer\s+([a-zA-Z0-9_\-\.=]{20,})')
        Severity = 'High'
        Description = 'Bearer authentication token'
        Remediation = 'Rotate token. Verify token expiration policy.'
        Entropy = $true
        FalsePositiveKeywords = @('token', 'your')
    }
    'OAuth Token' = @{
        Patterns = @("(?i)oauth[_-]?token[`"\s]*[:=][`"\s]*[`"\']([a-zA-Z0-9_\-\.=]{20,})[`"\']?")
        Severity = 'High'
        Description = 'OAuth access token'
        Remediation = 'Revoke token through OAuth provider.'
        Entropy = $true
        FalsePositiveKeywords = @('example')
    }
    'Basic Auth Credentials' = @{
        Patterns = @('(?i)Authorization:\s*Basic\s+([A-Za-z0-9+/=]{20,})')
        Severity = 'High'
        Description = 'HTTP Basic Authentication credentials'
        Remediation = 'Rotate credentials. Consider OAuth or API keys instead.'
        Entropy = $false
        FalsePositiveKeywords = @()
    }
    'Firebase URL' = @{
        Patterns = @('[a-z0-9.-]+\.firebaseio\.com')
        Severity = 'Low'
        Description = 'Firebase database URL'
        Remediation = 'Verify Firebase security rules are properly configured.'
        Entropy = $false
        FalsePositiveKeywords = @()
    }
    'Cloudinary URL' = @{
        Patterns = @('cloudinary://[0-9]+:[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+')
        Severity = 'High'
        Description = 'Cloudinary connection URL with credentials'
        Remediation = 'Regenerate API secret in Cloudinary dashboard.'
        Entropy = $false
        FalsePositiveKeywords = @()
    }
    'OpenAI API Key' = @{
        Patterns = @('sk-proj-[a-zA-Z0-9-]{48}', 'sk-[a-zA-Z0-9-]{48}')
        Severity = 'Critical'
        Description = 'OpenAI API Key detected.'
        Remediation = 'Revoke the API key immediately from the OpenAI dashboard.'
        Entropy = $false
        FalsePositiveKeywords = @()
    }
}

# File extensions to scan
$script:FileExtensions = @(
    '.txt', '.log', '.cfg', '.conf', '.config', '.ini', '.env', '.properties', '.envrc',
    '.json', '.xml', '.yaml', '.yml', '.toml', '.tfvars', '.tf', '.tfstate',
    '.js', '.ts', '.jsx', '.tsx', '.vue', '.svelte',
    '.py', '.pyc', '.pyw', '.pyx',
    '.java', '.class', '.jsp',
    '.cs', '.vb', '.fs',
    '.cpp', '.c', '.h', '.hpp', '.cc', '.cxx',
    '.php', '.phtml',
    '.rb', '.erb', '.rake',
    '.go', '.rs', '.swift', '.kt', '.scala',
    '.ps1', '.psm1', '.psd1', '.bat', '.cmd',
    '.sh', '.bash', '.zsh', '.fish', '.ksh',
    '.sql', '.db', '.sqlite',
    '.md', '.rst', '.adoc',
    '.doc', '.docx',
    '.gradle', '.sbt', '.maven', '.pom',
    '.dockerfile', '.dockerignore', '.containerfile',
    '.pem', '.key', '.pub', '.crt', '.cer', '.p12', '.pfx',
    '.ipynb', '.r', '.rmd'
)

# Calculate Shannon entropy
function Get-Entropy {
    param([string]$String)
    
    if ([string]::IsNullOrWhiteSpace($String) -or $String.Length -lt 8) {
        return 0
    }
    
    $charCount = @{}
    foreach ($char in $String.ToCharArray()) {
        if ($charCount.ContainsKey($char)) {
            $charCount[$char]++
        } else {
            $charCount[$char] = 1
        }
    }
    
    $entropy = 0.0
    $length = $String.Length
    
    foreach ($count in $charCount.Values) {
        $probability = $count / $length
        $entropy -= $probability * [Math]::Log($probability, 2)
    }
    
    return $entropy
}

# Check if string contains false positive keywords
function Test-FalsePositive {
    param(
        [string]$Value,
        [array]$FalsePositiveKeywords
    )
    
    $lowerValue = $Value.ToLower()
    foreach ($keyword in $FalsePositiveKeywords) {
        if ($lowerValue -match [regex]::Escape($keyword.ToLower())) {
            return $true
        }
    }
    return $false
}

# Load whitelist
function Get-Whitelist {
    param([string]$WhitelistPath)
    
    if ([string]::IsNullOrWhiteSpace($WhitelistPath) -or !(Test-Path $WhitelistPath)) {
        return @()
    }
    
    try {
        $content = Get-Content -Path $WhitelistPath -ErrorAction Stop
        $filteredContent = $content | Where-Object { $_ -notmatch '^\s*#' -and $_ -notmatch '^\s*$' }
        if ($null -eq $filteredContent) {
            return @()
        }
        return $filteredContent
    } catch {
        Write-LogMessage "Failed to load whitelist: $($_.Exception.Message)" "WARNING"
        return @()
    }
}

# Check if finding is whitelisted
function Test-Whitelisted {
    param(
        [string]$Finding,
        [string]$FilePath,
        [array]$Whitelist
    )
    
    foreach ($item in $Whitelist) {
        # Support file:pattern format
        if ($item -match '^([^:]+):(.+)$') {
            $filePattern = $Matches[1]
            $valuePattern = $Matches[2]

            if ($FilePath -like "*$filePattern*" -and $Finding -match $valuePattern) {
                return $true
            }
        } else {
            # Simple pattern matching (treat whitelist entry as literal)
            if ($Finding -match [regex]::Escape($item)) {
                return $true
            }
        }
    }
    return $false
}

# Get severity level value
function Get-SeverityValue {
    param([string]$Severity)
    # Write-Host "Determining severity value for: $Severity"
    switch ($Severity) {
        "Critical" { return 4 }
        "High" { return 3 }
        "Medium" { return 2 }
        "Low" { return 1 }
        default { return 0 }
    }
}

# Get context lines around a finding
function Get-ContextLines {
    param(
        [string]$Content,
        [int]$LineNumber,
        [int]$ContextLineCount
    )
    
    $lines = $Content -split "`n"
    $startLine = [Math]::Max(0, $LineNumber - $ContextLineCount - 1)
    $endLine = [Math]::Min($lines.Count - 1, $LineNumber + $ContextLineCount - 1)
    
    $context = @()
    for ($i = $startLine; $i -le $endLine; $i++) {
        $context += [PSCustomObject]@{
            LineNumber = $i + 1
            Content = $lines[$i]
            IsMatch = ($i -eq $LineNumber - 1)
        }
    }
    
    return $context
}

# Logging function
function Write-LogMessage {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    if ($QuietMode -and $Level -ne "ERROR" -and $Level -ne "CRITICAL") {
        return
    }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    if ($LogFile) {
        Add-Content -Path $LogFile -Value $logEntry -Encoding UTF8 -ErrorAction SilentlyContinue
    }
    
    if (-not $QuietMode) {
        switch ($Level) {
            "CRITICAL" { Write-Host $logEntry -ForegroundColor Red -BackgroundColor Black }
            "ERROR" { Write-Host $logEntry -ForegroundColor Red }
            "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
            "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
            "INFO" { if ($ShowProgress) { Write-Host $logEntry -ForegroundColor Cyan } }
            default { Write-Host $logEntry }
        }
    }
}

# Initialize log file
function Initialize-LogFile {
    param($LogPath)
    
    $logDir = Split-Path -Parent $LogPath
    if ($logDir -and !(Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    
    $header = @"
================================================================================
Enterprise Secret Scanner v3.0
================================================================================
Scan Date         : $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Root Directory    : $Directory
PowerShell Ver    : $($PSVersionTable.PSVersion)
Output Format     : $OutputFormat
Min Entropy       : $MinEntropy
Min Severity      : $MinSeverity
Max File Size     : $MaxFileSizeMB MB
Context Lines     : $ContextLines
Scan Git History  : $ScanGitHistory
Interactive Mode  : $Interactive
Excluded Folders  : $($ExcludeFolders -join ', ')
Excluded Files    : $($ExcludeFiles -join ', ')
Whitelist File    : $(if($WhitelistFile){$WhitelistFile}else{'None'})
Config File       : $(if($ConfigFile){$ConfigFile}else{'None'})
================================================================================

"@
    Set-Content -Path $LogPath -Value $header -Encoding UTF8
}

# Scan a single file for secrets
function Scan-FileForSecrets {
    param(
        [string]$FilePath,
        [hashtable]$Patterns,
        [array]$Whitelist,
        [double]$MinEntropyThreshold,
        [int]$MinSeverityLevel,
        [int]$Context
    )
    
    try {
        $fileInfo = Get-Item $FilePath -ErrorAction Stop
        
        if ($fileInfo.Length -gt ($MaxFileSizeMB * 1MB)) {
            return
        }
        
        $content = Get-Content -Path $FilePath -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($content)) {
            return
        }
        
        $lines = $content -split "`n"
        
        foreach ($category in $Patterns.Keys) {
            $patternInfo = $Patterns[$category]
            $severity = $patternInfo.Severity
            $severityValue = Get-SeverityValue $severity
            
            if ($severityValue -lt $MinSeverityLevel) {
                continue
            }
            
            foreach ($pattern in $patternInfo.Patterns) {
                try {
                    $matches = [regex]::Matches($content, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                    
                    foreach ($match in $matches) {
                        $matchedText = $match.Value
                        $secretValue = if ($match.Groups.Count -gt 1) { $match.Groups[1].Value } else { $matchedText }
                        
                        # Check false positive keywords
                        if (Test-FalsePositive -Value $secretValue -FalsePositiveKeywords $patternInfo.FalsePositiveKeywords) {
                            continue
                        }
                        
                        # Check entropy if required
                        $entropy = Get-Entropy $secretValue
                        if ($patternInfo.Entropy -and $entropy -lt $MinEntropyThreshold) {
                            continue
                        }
                        
                        # Check whitelist
                        if (Test-Whitelisted -Finding $matchedText -FilePath $FilePath -Whitelist $Whitelist) {
                            continue
                        }
                        
                        $lineNumber = ($content.Substring(0, $match.Index) -split "`n").Count
                        $contextLines = Get-ContextLines -Content $content -LineNumber $lineNumber -ContextLineCount $Context
                        
                        # Redact secret value
                        $displayValue = if ($ShowSecretValues) { 
                            $matchedText 
                        } else {
                            if ($matchedText.Length -le 10) {
                                "***REDACTED***"
                            } else {
                                $matchedText.Substring(0, [Math]::Min(10, $matchedText.Length)) + "***REDACTED***"
                            }
                        }
                        
                        if ($displayValue.Length -gt 150) {
                            $displayValue = $displayValue.Substring(0, 150) + "..."
                        }
                        
                        # Create finding object
                        $finding = [PSCustomObject]@{
                            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                            Category = $category
                            Severity = $severity
                            Description = $patternInfo.Description
                            Remediation = $patternInfo.Remediation
                            FilePath = $FilePath
                            LineNumber = $lineNumber
                            ColumnStart = $match.Index
                            MatchedValue = $displayValue
                            Entropy = [Math]::Round($entropy, 2)
                            ContextLines = $contextLines
                            FileExtension = $fileInfo.Extension
                            FileSize = $fileInfo.Length
                        }
                        
                        [void]$script:AllFindings.Add($finding)
                        
                        $logLevel = switch ($severity) {
                            "Critical" { "CRITICAL" }
                            "High"     { "ERROR" }
                            "Medium"   { "WARNING" }
                            "Low"      { "WARNING" }
                            default    { "INFO" }
                        }

                        $msg = "$category | ${FilePath}:$lineNumber | Entropy: $($finding.Entropy)"
                        Write-LogMessage $msg $logLevel

                        $contextMsg = "  └─ Matched: $($finding.MatchedValue)"
                        Write-LogMessage $contextMsg $logLevel
                    }
                } catch {
                    Write-LogMessage "Error processing pattern '$pattern' in $FilePath : $($_.Exception.Message)" "WARNING"
                }
            }
        }
        
        $script:ScannedFiles++
        
        if ($ShowProgress -and $script:ScannedFiles % 50 -eq 0) {
            $percent = [Math]::Round(($script:ScannedFiles / $script:TotalFiles) * 100, 1)
            Write-LogMessage "Progress: $script:ScannedFiles/$script:TotalFiles files ($percent%)" "INFO"
        }
        
    } catch {
        Write-LogMessage "Error scanning $FilePath : $($_.Exception.Message)" "ERROR"
    }
}

# Export findings to SARIF format (for GitHub Code Scanning)
function Export-SARIF {
    param(
        [array]$Findings,
        [string]$OutputPath
    )
    
    $rules = @()
    $results = @()
    
    $ruleIndex = @{}
    $ruleCounter = 0
    
    foreach ($finding in $Findings) {
        $ruleId = "secret-scanner/$($finding.Category -replace '[^a-zA-Z0-9-]', '-')"
        
        if (-not $ruleIndex.ContainsKey($ruleId)) {
            $ruleIndex[$ruleId] = $ruleCounter++
            
            $rules += @{
                id = $ruleId
                name = $finding.Category
                shortDescription = @{
                    text = $finding.Description
                }
                fullDescription = @{
                    text = "$($finding.Description). $($finding.Remediation)"
                }
                defaultConfiguration = @{
                    level = switch ($finding.Severity) {
                        "Critical" { "error" }
                        "High" { "error" }
                        "Medium" { "warning" }
                        "Low" { "note" }
                        default { "warning" }
                    }
                }
                properties = @{
                    tags = @("security", "secret", $finding.Severity.ToLower())
                    precision = "high"
                }
            }
        }
        
        $results += @{
            ruleId = $ruleId
            ruleIndex = $ruleIndex[$ruleId]
            message = @{
                text = "$($finding.Category) detected: $($finding.Description)"
            }
            locations = @(
                @{
                    physicalLocation = @{
                        artifactLocation = @{
                            uri = $finding.FilePath -replace '\\', '/'
                        }
                        region = @{
                            startLine = $finding.LineNumber
                            startColumn = 1
                        }
                    }
                }
            )
            properties = @{
                severity = $finding.Severity
                entropy = $finding.Entropy
                remediation = $finding.Remediation
            }
        }
    }
    
    $sarif = @{
        version = "2.1.0"
        '$schema' = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
        runs = @(
            @{
                tool = @{
                    driver = @{
                        name = "Enterprise Secret Scanner"
                        version = "3.0"
                        informationUri = "https://github.com/yourorg/secret-scanner"
                        rules = $rules
                    }
                }
                results = $results
            }
        )
    }
    
    $sarif | ConvertTo-Json -Depth 20 | Set-Content -Path $OutputPath -Encoding UTF8
}

# Export findings to various formats
function Export-Findings {
    param(
        [array]$Findings,
        [string]$Format,
        [string]$BasePath
    )
    
    switch ($Format) {
        "json" {
            $jsonPath = $BasePath -replace '\.log$', '.json'
            $Findings | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonPath -Encoding UTF8
            Write-LogMessage "JSON report: $jsonPath" "SUCCESS"
        }
        "csv" {
            $csvPath = $BasePath -replace '\.log$', '.csv'
            $Findings | Select-Object Timestamp, Severity, Category, FilePath, LineNumber, Entropy, MatchedValue, Description | 
                Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
            Write-LogMessage "CSV report: $csvPath" "SUCCESS"
        }
        "sarif" {
            $sarifPath = $BasePath -replace '\.log$', '.sarif'
            Export-SARIF -Findings $Findings -OutputPath $sarifPath
            Write-LogMessage "SARIF report: $sarifPath" "SUCCESS"
        }
        "html" {
            $htmlPath = $BasePath -replace '\.log$', '.html'
            $html = Generate-HTMLReport -Findings $Findings
            $html | Set-Content -Path $htmlPath -Encoding UTF8
            Write-LogMessage "HTML report: $htmlPath" "SUCCESS"
        }
    }
}

# Generate comprehensive HTML report
function Generate-HTMLReport {
    param([array]$Findings)
    
    $criticalCount = ($Findings | Where-Object {$_.Severity -eq 'Critical'}).Count
    $highCount = ($Findings | Where-Object {$_.Severity -eq 'High'}).Count
    $mediumCount = ($Findings | Where-Object {$_.Severity -eq 'Medium'}).Count
    $lowCount = ($Findings | Where-Object {$_.Severity -eq 'Low'}).Count
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secret Scanner Report - $(Get-Date -Format 'yyyy-MM-dd')</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; 
               background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
               padding: 20px; min-height: 100vh; }
        .container { max-width: 1400px; margin: 0 auto; }
        .header { background: white; padding: 30px; border-radius: 15px; box-shadow: 0 10px 40px rgba(0,0,0,0.1); margin-bottom: 30px; }
        .header h1 { color: #2d3748; font-size: 2.5em; margin-bottom: 10px; }
        .header .subtitle { color: #718096; font-size: 1.1em; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: white; padding: 25px; border-radius: 15px; box-shadow: 0 10px 40px rgba(0,0,0,0.1); text-align: center; }
        .stat-value { font-size: 3em; font-weight: bold; margin-bottom: 10px; }
        .stat-label { color: #718096; font-size: 1.1em; text-transform: uppercase; letter-spacing: 1px; }
        .critical-value { color: #dc3545; }
        .high-value { color: #fd7e14; }
        .medium-value { color: #ffc107; }
        .low-value { color: #28a745; }
        .total-value { color: #667eea; }
        .findings-section { background: white; padding: 30px; border-radius: 15px; box-shadow: 0 10px 40px rgba(0,0,0,0.1); }
        .finding-card { background: #f8f9fa; padding: 20px; margin-bottom: 20px; border-radius: 10px; border-left: 5px solid #ccc; }
        .finding-card.critical { border-left-color: #dc3545; background: #fff5f5; }
        .finding-card.high { border-left-color: #fd7e14; background: #fff8f0; }
        .finding-card.medium { border-left-color: #ffc107; background: #fffbf0; }
        .finding-card.low { border-left-color: #28a745; background: #f0fff4; }
        .finding-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
        .finding-title { font-size: 1.3em; font-weight: bold; color: #2d3748; }
        .severity-badge { padding: 5px 15px; border-radius: 20px; font-size: 0.85em; font-weight: bold; color: white; }
        .badge-critical { background: #dc3545; }
        .badge-high { background: #fd7e14; }
        .badge-medium { background: #ffc107; color: #333; }
        .badge-low { background: #28a745; }
        .finding-meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 15px; }
        .meta-item { color: #4a5568; }
        .meta-label { font-weight: bold; color: #2d3748; }
        .code-block { background: #2d3748; color: #e2e8f0; padding: 15px; border-radius: 8px; font-family: 'Courier New', monospace; 
                      overflow-x: auto; margin-top: 15px; font-size: 0.9em; }
        .context-line { padding: 5px 10px; border-left: 3px solid transparent; }
        .context-line.match { background: #fff3cd; border-left-color: #ffc107; color: #856404; font-weight: bold; }
        .line-number { display: inline-block; width: 50px; color: #a0aec0; text-align: right; margin-right: 15px; user-select: none; }
        .remediation-box { background: #e6fffa; border-left: 4px solid #38b2ac; padding: 15px; border-radius: 5px; margin-top: 15px; }
        .remediation-title { font-weight: bold; color: #234e52; margin-bottom: 5px; }
        .remediation-text { color: #2c7a7b; }
        .no-findings { text-align: center; padding: 60px; color: #718096; }
        .no-findings-icon { font-size: 4em; margin-bottom: 20px; }
        @media print { body { background: white; } .stat-card, .findings-section { box-shadow: none; border: 1px solid #e2e8f0; } }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Secret Scanner Report</h1>
            <div class="subtitle">Generated on $(Get-Date -Format "MMMM dd, yyyy 'at' HH:mm:ss") | Directory: $Directory</div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value critical-value">$criticalCount</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card">
                <div class="stat-value high-value">$highCount</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card">
                <div class="stat-value medium-value">$mediumCount</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card">
                <div class="stat-value low-value">$lowCount</div>
                <div class="stat-label">Low</div>
            </div>
            <div class="stat-card">
                <div class="stat-value total-value">$($Findings.Count)</div>
                <div class="stat-label">Total Findings</div>
            </div>
        </div>
        
        <div class="findings-section">
            <h2 style="margin-bottom: 25px; color: #2d3748;">Detailed Findings</h2>
"@
    
    if ($Findings.Count -eq 0) {
        $html += @"
            <div class="no-findings">
                <div class="no-findings-icon">✅</div>
                <h3>No Secrets Detected</h3>
                <p>All scanned files appear clean.</p>
            </div>
"@
    } else {
        foreach ($finding in ($Findings | Sort-Object @{ Expression = { Get-SeverityValue $_.Severity }; Descending = $true }, @{ Expression = { $_.Category }; Descending = $false })) {
            $severityClass = $finding.Severity.ToLower()
            $contextHtml = ""
            
            if ($finding.ContextLines) {
                foreach ($line in $finding.ContextLines) {
                    $lineClass = if ($line.IsMatch) { "match" } else { "" }
                    $escapedContent = [System.Web.HttpUtility]::HtmlEncode($line.Content)
                    $contextHtml += "<div class='context-line $lineClass'><span class='line-number'>$($line.LineNumber)</span>$escapedContent</div>"
                }
            }
            
            $html += @"
            <div class="finding-card $severityClass">
                <div class="finding-header">
                    <div class="finding-title">$($finding.Category)</div>
                    <span class="severity-badge badge-$severityClass">$($finding.Severity)</span>
                </div>
                <div class="finding-meta">
                    <div class="meta-item"><span class="meta-label">File:</span> $($finding.FilePath)</div>
                    <div class="meta-item"><span class="meta-label">Line:</span> $($finding.LineNumber)</div>
                    <div class="meta-item"><span class="meta-label">Entropy:</span> $($finding.Entropy)</div>
                </div>
                <div style="margin-bottom: 10px; color: #4a5568;">
                    <strong>Description:</strong> $($finding.Description)
                </div>
                <div style="margin-bottom: 10px; color: #4a5568;">
                    <strong>Matched Value:</strong> <code style="background: #e2e8f0; padding: 2px 6px; border-radius: 3px;">$([System.Web.HttpUtility]::HtmlEncode($finding.MatchedValue))</code>
                </div>
                $(if ($contextHtml) { "<div class='code-block'>$contextHtml</div>" })
                <div class="remediation-box">
                    <div class="remediation-title">🔧 Remediation Steps</div>
                    <div class="remediation-text">$($finding.Remediation)</div>
                </div>
            </div>
"@
        }
    }
    
    $html += @"
        </div>
    </div>
</body>
</html>
"@
    
    return $html
}

# Scan git history for secrets
function Scan-GitHistory {
    param(
        [string]$RepoPath,
        [hashtable]$Patterns,
        [array]$Whitelist,
        [double]$MinEntropyThreshold,
        [int]$MinSeverityLevel
    )
    
    Write-LogMessage "Scanning git history (this may take a while)..." "INFO"
    
    Push-Location $RepoPath
    
    try {
        # Check if git is available
        $gitVersion = git --version 2>$null
        if (-not $gitVersion) {
            Write-LogMessage "Git not found. Skipping git history scan." "WARNING"
            return
        }
        
        Write-LogMessage "Git detected: $gitVersion" "INFO"
        
        # Get all commit hashes
        $commits = git rev-list --all 2>$null
        if (-not $commits) {
            Write-LogMessage "No git commits found or not a git repository." "WARNING"
            return
        }
        
        $commitCount = ($commits | Measure-Object).Count
        Write-LogMessage "Found $commitCount commits to scan" "INFO"
        
        $processedCommits = 0
        
        foreach ($commit in $commits) {
            $processedCommits++
            
            if ($processedCommits % 100 -eq 0) {
                Write-LogMessage "Git history: $processedCommits/$commitCount commits scanned" "INFO"
            }
            
            # Get commit details
            $commitInfo = git show --format="%H|%an|%ae|%ad|%s" --no-patch $commit 2>$null
            if (-not $commitInfo) { continue }
            
            $parts = $commitInfo -split '\|', 5
            $commitHash = $parts[0]
            $author = $parts[1]
            $email = $parts[2]
            $date = $parts[3]
            $message = $parts[4]
            
            # Get commit diff
            $diff = git show $commit 2>$null
            if (-not $diff) { continue }
            
            # Scan diff content
            foreach ($category in $Patterns.Keys) {
                $patternInfo = $Patterns[$category]
                $severity = $patternInfo.Severity
                $severityValue = Get-SeverityValue $severity
                
                if ($severityValue -lt $MinSeverityLevel) { continue }
                
                foreach ($pattern in $patternInfo.Patterns) {
                    try {
                        $matches = [regex]::Matches($diff, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                        
                        foreach ($match in $matches) {
                            $matchedText = $match.Value
                            $secretValue = if ($match.Groups.Count -gt 1) { $match.Groups[1].Value } else { $matchedText }
                            
                            if (Test-FalsePositive -Value $secretValue -FalsePositiveKeywords $patternInfo.FalsePositiveKeywords) {
                                continue
                            }
                            
                            $entropy = Get-Entropy $secretValue
                            if ($patternInfo.Entropy -and $entropy -lt $MinEntropyThreshold) {
                                continue
                            }
                            
                            if (Test-Whitelisted -Finding $matchedText -FilePath $commitHash -Whitelist $Whitelist) {
                                continue
                            }
                            
                            $displayValue = if ($ShowSecretValues) { 
                                $matchedText 
                            } else {
                                if ($matchedText.Length -le 10) {
                                    "***REDACTED***"
                                } else {
                                    $matchedText.Substring(0, [Math]::Min(10, $matchedText.Length)) + "***REDACTED***"
                                }
                            }
                            
                            $finding = [PSCustomObject]@{
                                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                                Category = $category
                                Severity = $severity
                                Description = $patternInfo.Description
                                Remediation = "$($patternInfo.Remediation) This secret was found in git history (commit $($commitHash.Substring(0,8))). Consider using git-filter-branch or BFG Repo-Cleaner to remove it from history."
                                FilePath = "GIT HISTORY: Commit $($commitHash.Substring(0,8))"
                                LineNumber = 0
                                ColumnStart = $match.Index
                                MatchedValue = $displayValue
                                Entropy = [Math]::Round($entropy, 2)
                                ContextLines = @()
                                GitCommit = $commitHash
                                GitAuthor = $author
                                GitEmail = $email
                                GitDate = $date
                                GitMessage = $message
                                FileExtension = ".git"
                                FileSize = 0
                            }
                            
                            [void]$script:AllFindings.Add($finding)
                            
                            $logLevel = switch ($severity) {
                                "Critical" { "CRITICAL" }
                                "High"     { "ERROR" }
                                "Medium"   { "WARNING" }
                                "Low"      { "WARNING" }
                                default    { "INFO" }
                            }

                            $msg = "$category | Git commit $($commitHash.Substring(0,8)) by $author | Entropy: $($finding.Entropy)"
                            Write-LogMessage $msg $logLevel

                            $contextMsg = "  └─ Matched: $($finding.MatchedValue)"
                            Write-LogMessage $contextMsg $logLevel
                        }
                    } catch {
                        # Silently continue on regex errors in git history
                    }
                }
            }
        }
        
        Write-LogMessage "Git history scan complete: $processedCommits commits scanned" "SUCCESS"
        
    } catch {
        Write-LogMessage "Error scanning git history: $($_.Exception.Message)" "ERROR"
    } finally {
        Pop-Location
    }
}

# Interactive remediation mode
function Start-InteractiveRemediation {
    param([array]$Findings)
    
    if ($Findings.Count -eq 0) {
        Write-Host "`n✓ No findings to remediate!" -ForegroundColor Green
        return
    }
    
    Write-Host "`n" -NoNewline
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║           INTERACTIVE REMEDIATION MODE                        ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    
    $currentIndex = 0
    
    while ($currentIndex -lt $Findings.Count) {
        $finding = $Findings[$currentIndex]
        
        Clear-Host
        Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host " Finding $($currentIndex + 1) of $($Findings.Count)" -ForegroundColor White
        Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Category:    " -NoNewline -ForegroundColor Yellow
        Write-Host $finding.Category -ForegroundColor White
        Write-Host "Severity:    " -NoNewline -ForegroundColor Yellow
        Write-Host $finding.Severity -ForegroundColor $(switch ($finding.Severity) {
            "Critical" { "Red" }
            "High" { "Red" }
            "Medium" { "Yellow" }
            "Low" { "Green" }
        })
        Write-Host "File:        " -NoNewline -ForegroundColor Yellow
        Write-Host $finding.FilePath -ForegroundColor White
        Write-Host "Line:        " -NoNewline -ForegroundColor Yellow
        Write-Host $finding.LineNumber -ForegroundColor White
        Write-Host "Entropy:     " -NoNewline -ForegroundColor Yellow
        Write-Host $finding.Entropy -ForegroundColor White
        Write-Host ""
        Write-Host "Description: " -ForegroundColor Yellow
        Write-Host "  $($finding.Description)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "Matched Value: " -ForegroundColor Yellow
        Write-Host "  $($finding.MatchedValue)" -ForegroundColor Red
        Write-Host ""
        Write-Host "Remediation: " -ForegroundColor Green
        Write-Host "  $($finding.Remediation)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "───────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "[O]pen file  [W]hitelist  [N]ext  [P]revious  [Q]uit" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Your choice: " -NoNewline -ForegroundColor Yellow
        
        $choice = Read-Host
        
        switch ($choice.ToUpper()) {
            "O" {
                if (Test-Path $finding.FilePath) {
                    Start-Process notepad.exe -ArgumentList $finding.FilePath
                } else {
                    Write-Host "File not found or in git history." -ForegroundColor Red
                    Start-Sleep -Seconds 2
                }
            }
            "W" {
                if ($WhitelistFile) {
                    Add-Content -Path $WhitelistFile -Value $finding.MatchedValue
                    Write-Host "Added to whitelist: $WhitelistFile" -ForegroundColor Green
                } else {
                    $newWhitelist = Read-Host "Enter whitelist file path"
                    if ($newWhitelist) {
                        $script:WhitelistFile = $newWhitelist
                        Add-Content -Path $script:WhitelistFile -Value $finding.MatchedValue
                        Write-Host "Created whitelist and added entry." -ForegroundColor Green
                    }
                }
                Start-Sleep -Seconds 2
            }
            "N" {
                if ($currentIndex -lt $Findings.Count - 1) {
                    $currentIndex++
                } else {
                    Write-Host "Last finding reached." -ForegroundColor Yellow
                    Start-Sleep -Seconds 1
                }
            }
            "P" {
                if ($currentIndex -gt 0) {
                    $currentIndex--
                } else {
                    Write-Host "First finding reached." -ForegroundColor Yellow
                    Start-Sleep -Seconds 1
                }
            }
            "Q" {
                Write-Host "Exiting interactive mode..." -ForegroundColor Yellow
                return
            }
            default {
                $currentIndex++
            }
        }
    }
    
    Write-Host "`nAll findings reviewed!" -ForegroundColor Green
    Start-Sleep -Seconds 2
}

# Main execution
try {
    $ErrorActionPreference = "Stop"
    
    # Resolve directory to full path
    $Directory = (Resolve-Path $Directory).Path
    
    # Initialize log
    $LogFile = Join-Path (Get-Location) $LogFile
    Initialize-LogFile $LogFile
    
    Write-LogMessage "═══════════════════════════════════════════════════════════" "INFO"
    Write-LogMessage "Enterprise Secret Scanner v3.0 - Starting scan..." "INFO"
    Write-LogMessage "═══════════════════════════════════════════════════════════" "INFO"
    
    # Load configuration if specified
    if ($ConfigFile -and (Test-Path $ConfigFile)) {
        Write-LogMessage "Loading configuration from: $ConfigFile" "INFO"
        # Future: Load custom patterns and settings from config file
    }
    
    # Load whitelist
    $whitelist = Get-Whitelist $WhitelistFile
    if ($whitelist.Count -gt 0) {
        Write-LogMessage "Loaded $($whitelist.Count) whitelist entries" "INFO"
    }
    
    $minSeverityLevel = Get-SeverityValue $MinSeverity
    
    # Discover files to scan
    Write-LogMessage "Discovering files to scan..." "INFO"
    
    $excludeFolderPatterns = $ExcludeFolders | ForEach-Object { "*\" + $_ + "\*" }
    $allFiles = Get-ChildItem -Path $Directory -Recurse -File -ErrorAction SilentlyContinue
    
    $filesToScan = $allFiles | Where-Object {
        $file = $_
        $filePath = $file.FullName
        
        $excludedByFolder = $false
        foreach ($pattern in $excludeFolderPatterns) {
            if ($filePath -like $pattern) {
                $excludedByFolder = $true
                break
            }
        }
        
        $excludedByFile = $false
        foreach ($pattern in $ExcludeFiles) {
            if ($file.Name -like $pattern) {
                $excludedByFile = $true
                break
            }
        }
        
        -not $excludedByFolder -and 
        -not $excludedByFile -and 
        $file.Extension -in $script:FileExtensions -and 
        $file.Length -le ($MaxFileSizeMB * 1MB)
    }
    
    $script:TotalFiles = $filesToScan.Count
    Write-LogMessage "Found $script:TotalFiles files to scan" "SUCCESS"
    
    if ($script:TotalFiles -eq 0) {
        Write-LogMessage "No files found matching criteria." "WARNING"
        exit 0
    }
    
    # Start file scanning
    $psVersion = $PSVersionTable.PSVersion.Major
    
    if ($psVersion -ge 7) {
        Write-LogMessage "Starting optimized parallel scan (PowerShell $psVersion)..." "INFO"
        
        # ═══ PERFORMANCE OPTIMIZATION: CACHING ═══
        $cache = $null
        $filesToActuallyScan = $filesToScan
        
        if ($UseCache -and $performanceModulesLoaded) {
            Write-LogMessage "Initializing file cache..." "INFO"
            $cache = Initialize-ScanCache -CacheDirectory $CacheDirectory
            
            $cacheStats = Get-CacheStatistics -Cache $cache
            Write-LogMessage "Cache loaded: $($cacheStats.TotalCachedFiles) entries" "INFO"
            
            # Filter to only changed files
            $filesToActuallyScan = $filesToScan | Where-Object {
                Test-FileChanged -File $_ -Cache $cache
            }
            
            $skippedCount = $filesToScan.Count - $filesToActuallyScan.Count
            $cacheHitRate = if ($filesToScan.Count -gt 0) {
                [Math]::Round(($skippedCount / $filesToScan.Count) * 100, 1)
            } else { 0 }
            
            Write-LogMessage "Cache hit: $cacheHitRate% ($skippedCount files skipped)" "SUCCESS"
        }
        
        # ═══ PERFORMANCE OPTIMIZATION: MEMORY RECOMMENDATIONS ═══
        if ($performanceModulesLoaded -and $filesToActuallyScan.Count -gt 0) {
            $avgSize = ($filesToActuallyScan | Measure-Object -Property Length -Average).Average / 1KB
            $memRec = Get-MemoryRecommendations `
                -FileCount $filesToActuallyScan.Count `
                -ThrottleLimit $ThrottleLimit `
                -AverageFileSizeKB $avgSize
            
            if ($memRec.Recommendations.Count -gt 0) {
                foreach ($rec in $memRec.Recommendations) {
                    Write-LogMessage $rec "WARNING"
                }
            }
        }
        
        # ═══ PERFORMANCE OPTIMIZATION: OPTIMIZED PARALLEL SCAN ═══
        if ($performanceModulesLoaded) {
            $parallelResults = Invoke-OptimizedParallelScan `
                -Files $filesToActuallyScan `
                -Patterns $script:SecretPatterns `
                -Whitelist $whitelist `
                -MinEntropy $MinEntropy `
                -MinSeverityLevel $minSeverityLevel `
                -ContextLines $ContextLines `
                -ThrottleLimit $ThrottleLimit `
                -ShowSecretValues $ShowSecretValues `
                -MaxFileSizeMB $MaxFileSizeMB `
                -GetEntropyFunction ${function:Get-Entropy} `
                -GetSeverityValueFunction ${function:Get-SeverityValue} `
                -TestWhitelistedFunction ${function:Test-Whitelisted} `
                -TestFalsePositiveFunction ${function:Test-FalsePositive} `
                -GetContextLinesFunction ${function:Get-ContextLines}
        }
        else {
            # Fallback to standard parallel processing
            Write-LogMessage "Using standard parallel processing..." "INFO"
            
            $GetEntropyDef       = ${function:Get-Entropy}.ToString()
            $GetSeverityValueDef = ${function:Get-SeverityValue}.ToString()
            $TestWhitelistedDef  = ${function:Test-Whitelisted}.ToString()
            $TestFalsePosDef     = ${function:Test-FalsePositive}.ToString()
            $GetContextLinesDef  = ${function:Get-ContextLines}.ToString()

            $parallelResults = $filesToActuallyScan | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
                $file = $_
                $localFindings = [System.Collections.Generic.List[object]]::new()

                $patterns = $using:SecretPatterns
                $whitelist = $using:whitelist
                $minEntropy = $using:MinEntropy
                $minSevLevel = $using:minSeverityLevel
                $context = $using:ContextLines
                $showVals = $using:ShowSecretValues
                $maxSize = $using:MaxFileSizeMB

                ${function:Get-Entropy}        = $using:GetEntropyDef
                ${function:Get-SeverityValue}  = $using:GetSeverityValueDef
                ${function:Test-Whitelisted}   = $using:TestWhitelistedDef
                ${function:Test-FalsePositive} = $using:TestFalsePosDef
                ${function:Get-ContextLines}   = $using:GetContextLinesDef
                
                try {
                    $fileInfo = Get-Item $file.FullName -ErrorAction Stop

                    if ($fileInfo.Length -gt ($maxSize * 1MB)) { 
                        return [PSCustomObject]@{ File = $file.FullName; Findings = $localFindings }
                    }
                    
                    $content = Get-Content -Path $file.FullName -Raw -ErrorAction Stop
                    if ([string]::IsNullOrWhiteSpace($content)) { 
                        return [PSCustomObject]@{ File = $file.FullName; Findings = $localFindings }
                    }
                    
                    foreach ($category in $patterns.Keys) {
                        $patternInfo = $patterns[$category]
                        $severity = $patternInfo.Severity
                        $severityValue = Get-SeverityValue $severity
                        
                        if ($severityValue -lt $minSevLevel) { continue }
                        
                        foreach ($pattern in $patternInfo.Patterns) {
                            try {
                                $matches = [regex]::Matches($content, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                                
                                foreach ($match in $matches) {
                                    $matchedText = $match.Value
                                    $secretValue = if ($match.Groups.Count -gt 1) { $match.Groups[1].Value } else { $matchedText }
                                    
                                    if (Test-FalsePositive -Value $secretValue -FalsePositiveKeywords $patternInfo.FalsePositiveKeywords) {
                                        continue
                                    }
                                    
                                    $entropy = Get-Entropy $secretValue
                                    if ($patternInfo.Entropy -and $entropy -lt $minEntropy) { continue }
                                    
                                    if (Test-Whitelisted -Finding $matchedText -FilePath $file.FullName -Whitelist $whitelist) { continue }
                                    
                                    $lineNumber = ($content.Substring(0, $match.Index) -split "`n").Count
                                    $contextLines = Get-ContextLines -Content $content -LineNumber $lineNumber -ContextLineCount $context
                                    
                                    $displayValue = if ($showVals) { 
                                        $matchedText 
                                    } else {
                                        if ($matchedText.Length -le 10) {
                                            "***REDACTED***"
                                        } else {
                                            $matchedText.Substring(0, [Math]::Min(10, $matchedText.Length)) + "***REDACTED***"
                                        }
                                    }
                                    
                                    if ($displayValue.Length -gt 150) {
                                        $displayValue = $displayValue.Substring(0, 150) + "..."
                                    }
                                    
                                    $finding = [PSCustomObject]@{
                                        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                                        Category = $category
                                        Severity = $severity
                                        Description = $patternInfo.Description
                                        Remediation = $patternInfo.Remediation
                                        FilePath = $file.FullName
                                        LineNumber = $lineNumber
                                        ColumnStart = $match.Index
                                        MatchedValue = $displayValue
                                        Entropy = [Math]::Round($entropy, 2)
                                        ContextLines = $contextLines
                                        FileExtension = $fileInfo.Extension
                                        FileSize = $fileInfo.Length
                                    }
                                    
                                    $localFindings.Add($finding)
                                }
                            } catch {
                                # Silently continue on regex errors
                            }
                        }
                    }
                } catch {
                    # Error handling in parallel threads
                }

                [PSCustomObject]@{
                    File = $file.FullName
                    Findings = $localFindings
                }
            }
        }

        # Update cache if enabled
        if ($UseCache -and $cache -and $performanceModulesLoaded) {
            Write-LogMessage "Updating cache..." "INFO"
            
            foreach ($result in $parallelResults) {
                if (-not $result.Skipped) {
                    $file = Get-Item $result.File -ErrorAction SilentlyContinue
                    if ($file) {
                        $categories = $result.Findings | Select-Object -ExpandProperty Category -Unique
                        Update-FileCache `
                            -File $file `
                            -Cache $cache `
                            -FindingsCount $result.Findings.Count `
                            -FindingCategories $categories
                    }
                }
            }
            
            # Optimize and save cache
            Optimize-ScanCache -Cache $cache -CurrentFiles $filesToScan
            Save-ScanCache -Cache $cache
            
            $finalStats = Get-CacheStatistics -Cache $cache
            Write-LogMessage "Cache updated: $($finalStats.TotalCachedFiles) entries" "SUCCESS"
        }

        # Aggregate results
        $script:ScannedFiles = $parallelResults.Count
        $allParallelFindings = $parallelResults.Findings | ForEach-Object { $_ }
        
        if ($allParallelFindings) {
            foreach ($finding in ($allParallelFindings | Sort-Object @{ Expression = { Get-SeverityValue $_.Severity }; Descending = $true }, FilePath, LineNumber)) {
                $msg = "[$($finding.Severity)] $($finding.Category) | $($finding.FilePath):$($finding.LineNumber) | Entropy: $($finding.Entropy)"
                Write-LogMessage $msg "CRITICAL"
                
                $contextMsg = "  └─ Matched: $($finding.MatchedValue)"
                Write-LogMessage $contextMsg "CRITICAL"
            }
            $script:AllFindings.AddRange(@($allParallelFindings))
        }
        
        # Display memory usage if available
        if ($performanceModulesLoaded) {
            $memUsage = Get-MemoryUsage
            Write-LogMessage "Peak memory usage: $($memUsage.PeakWorkingSetMB) MB" "INFO"
        }

    } else {
        Write-LogMessage "Starting sequential scan (PowerShell $psVersion)..." "INFO"
        
        foreach ($file in $filesToScan) {
            Scan-FileForSecrets -FilePath $file.FullName -Patterns $script:SecretPatterns `
                -Whitelist $whitelist -MinEntropyThreshold $MinEntropy `
                -MinSeverityLevel $minSeverityLevel -Context $ContextLines
        }
    }
    
    # Scan git history if requested
    if ($ScanGitHistory) {
        Scan-GitHistory -RepoPath $Directory -Patterns $script:SecretPatterns `
            -Whitelist $whitelist -MinEntropyThreshold $MinEntropy -MinSeverityLevel $minSeverityLevel
    }
    
    $endTime = Get-Date
    $duration = $endTime - $script:StartTime
    
    Write-LogMessage "Scan completed in $($duration.TotalSeconds.ToString('F2')) seconds" "SUCCESS"
    Write-LogMessage "Files processed: $script:ScannedFiles" "INFO"
    
    # Export findings
    if ($OutputFormat -ne "text" -and $script:AllFindings.Count -gt 0) {
        Export-Findings -Findings $script:AllFindings -Format $OutputFormat -BasePath $LogFile
    }
    
    # Generate comprehensive HTML report if requested
    if ($GenerateReport -and $script:AllFindings.Count -gt 0) {
        $htmlPath = $LogFile -replace '\.log$', '.html'
        $html = Generate-HTMLReport -Findings $script:AllFindings
        $html | Set-Content -Path $htmlPath -Encoding UTF8
        Write-LogMessage "Comprehensive report generated: $htmlPath" "SUCCESS"
    }
    
    # Display summary
    $foundSecrets = $script:AllFindings.Count
    $criticalCount = ($script:AllFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $highCount = ($script:AllFindings | Where-Object { $_.Severity -eq 'High' }).Count
    $mediumCount = ($script:AllFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
    $lowCount = ($script:AllFindings | Where-Object { $_.Severity -eq 'Low' }).Count
    
    if (-not $QuietMode) {
        Write-Host "`n"
        Write-Host "╔════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "║                          SCAN SUMMARY                                      ║" -ForegroundColor Cyan
        Write-Host "╚════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  Directory Scanned    : " -NoNewline -ForegroundColor White
        Write-Host $Directory -ForegroundColor Gray
        Write-Host "  Files Processed      : " -NoNewline -ForegroundColor White
        Write-Host "$script:ScannedFiles / $script:TotalFiles" -ForegroundColor Gray
        Write-Host "  Duration             : " -NoNewline -ForegroundColor White
        Write-Host "$($duration.TotalSeconds.ToString('F2')) seconds" -ForegroundColor Gray
        Write-Host "  Log File             : " -NoNewline -ForegroundColor White
        Write-Host $LogFile -ForegroundColor Gray
        Write-Host ""
        
        # Display optimization statistics
        if ($UseCache -and $performanceModulesLoaded -and $cache) {
            Write-Host ""
            Write-Host "  Cache Statistics:" -ForegroundColor White
            $cacheStats = Get-CacheStatistics -Cache $cache
            Write-Host "    Cached Files       : " -NoNewline -ForegroundColor White
            Write-Host $cacheStats.TotalCachedFiles -ForegroundColor Gray
            Write-Host "    Files with Findings: " -NoNewline -ForegroundColor White
            Write-Host $cacheStats.FilesWithFindings -ForegroundColor Gray
            Write-Host "    Last Updated       : " -NoNewline -ForegroundColor White
            Write-Host $cacheStats.LastUpdated -ForegroundColor Gray
        }
        
        if ($performanceModulesLoaded) {
            $memUsage = Get-MemoryUsage
            Write-Host ""
            Write-Host "  Memory Statistics:" -ForegroundColor White
            Write-Host "    Peak Usage         : " -NoNewline -ForegroundColor White
            Write-Host "$($memUsage.PeakWorkingSetMB) MB" -ForegroundColor Gray
            Write-Host "    Current Usage      : " -NoNewline -ForegroundColor White
            Write-Host "$($memUsage.WorkingSetMB) MB" -ForegroundColor Gray
        }
        
        Write-Host ""
        Write-Host "  Findings by Severity:" -ForegroundColor White
        Write-Host "    Critical           : " -NoNewline -ForegroundColor White
        Write-Host $criticalCount -ForegroundColor $(if ($criticalCount -gt 0) { "Red" } else { "Green" })
        Write-Host "    High               : " -NoNewline -ForegroundColor White
        Write-Host $highCount -ForegroundColor $(if ($highCount -gt 0) { "Red" } else { "Green" })
        Write-Host "    Medium             : " -NoNewline -ForegroundColor White
        Write-Host $mediumCount -ForegroundColor $(if ($mediumCount -gt 0) { "Yellow" } else { "Green" })
        Write-Host "    Low                : " -NoNewline -ForegroundColor White
        Write-Host $lowCount -ForegroundColor $(if ($lowCount -gt 0) { "Yellow" } else { "Green" })
        Write-Host "    ─────────────────────" -ForegroundColor DarkGray
        Write-Host "    Total              : " -NoNewline -ForegroundColor White
        Write-Host $foundSecrets -ForegroundColor $(if ($foundSecrets -gt 0) { "Red" } else { "Green" })
        Write-Host ""
        Write-Host "╚════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    }
    
    # Interactive mode
    if ($Interactive -and $foundSecrets -gt 0) {
        Start-InteractiveRemediation -Findings $script:AllFindings
    }
    
    # Final status and exit
    if ($foundSecrets -gt 0) {
        if (-not $QuietMode) {
            Write-Host ""
            Write-Host "⚠️  WARNING: Potential secrets detected!" -ForegroundColor Red
            Write-Host ""
            Write-Host "Recommended Actions:" -ForegroundColor Yellow
            Write-Host "  1. Review all findings immediately" -ForegroundColor Yellow
            Write-Host "  2. Rotate compromised credentials" -ForegroundColor Yellow
            Write-Host "  3. Remove secrets from code" -ForegroundColor Yellow
            Write-Host "  4. Use environment variables or secrets management" -ForegroundColor Yellow
            Write-Host "  5. Consider using git-filter-branch or BFG if secrets are in git history" -ForegroundColor Yellow
            Write-Host ""
        }
        
        if ($criticalCount -gt 0) {
            Write-Host "🚨 $criticalCount CRITICAL findings require IMMEDIATE attention!" -ForegroundColor Red -BackgroundColor Black
            Write-Host ""
        }
        
        if ($FailOnCritical -and $criticalCount -gt 0) {
            exit 2
        }
        
        exit 1
    } else {
        if (-not $QuietMode) {
            Write-Host ""
            Write-Host "✅ No potential secrets detected in scanned files." -ForegroundColor Green
            Write-Host ""
        }
        exit 0
    }
    
} catch {
    $errorMsg = "Fatal error: $($_.Exception.Message)"
    Write-LogMessage $errorMsg "ERROR"
    Write-Host ""
    Write-Host "💥 $errorMsg" -ForegroundColor Red
    Write-Host ""
    Write-Host "Stack Trace:" -ForegroundColor Yellow
    Write-Host $_.ScriptStackTrace -ForegroundColor Gray
    exit 3
}