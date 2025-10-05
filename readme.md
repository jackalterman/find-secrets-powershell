# Enterprise Secret Scanner

A comprehensive, enterprise-grade PowerShell tool for detecting secrets, credentials, API keys, and other sensitive information in your codebase and git history.

## 🚀 Features

### Core Capabilities
- **50+ Pre-defined Secret Patterns** - Detects AWS keys, GitHub tokens, API keys, private keys, database credentials, and more
- **Entropy Analysis** - Uses Shannon entropy calculation to identify high-entropy secrets
- **Git History Scanning** - Scans commit history to find secrets that may have been removed but still exist in history
- **Multi-format Output** - Export results as text, JSON, CSV, HTML, or SARIF (GitHub Code Scanning compatible)
- **Parallel Processing** - Multi-threaded scanning for faster results (PowerShell 7+)
- **Interactive Remediation** - Step through findings with guided remediation actions
- **Whitelist Support** - Exclude known false positives
- **Context Display** - Shows surrounding code lines for better understanding
- **Comprehensive Reporting** - Generate beautiful HTML reports with statistics and charts

### Security Features
- Secret value redaction by default (use `-ShowSecretValues` only for debugging)
- False positive detection using keyword matching
- Configurable severity levels (Critical, High, Medium, Low)
- File size limits to prevent memory issues
- Extensive file type support (60+ extensions)

## 📋 Requirements

- Windows PowerShell 5.1 or PowerShell 7+
- Windows Operating System
- Git (optional, only required for `-ScanGitHistory` feature)

## 📥 Installation

No installation required! Just download the script and run it with PowerShell.

```powershell
# Download the script
Invoke-WebRequest -Uri "https://your-repo/find_secrets.ps1" -OutFile "find_secrets.ps1"

# Or clone the repository
git clone https://github.com/yourorg/secret-scanner.git
cd secret-scanner
```

## 🎯 Quick Start

```powershell
# Basic scan of current directory
.\find_secrets.ps1 -Directory .

# Scan with JSON output
.\find_secrets.ps1 -Directory "C:\MyProject" -OutputFormat json

# Scan with HTML report generation
.\find_secrets.ps1 -Directory . -GenerateReport

# Scan git history (WARNING: can be slow on large repos)
.\find_secrets.ps1 -Directory . -ScanGitHistory

# High severity findings only
.\find_secrets.ps1 -Directory . -MinSeverity High

# Interactive mode for remediation
.\find_secrets.ps1 -Directory . -Interactive
```

## 📖 Usage

### Basic Syntax

```powershell
.\find_secrets.ps1 -Directory <path> [options]
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-Directory` | String | *Required* | Root directory to scan |
| `-OutputFormat` | String | `text` | Output format: text, json, csv, html, sarif |
| `-LogFile` | String | `secret-scan-TIMESTAMP.log` | Log file path |
| `-MinSeverity` | String | `Low` | Minimum severity: Low, Medium, High, Critical |
| `-MinEntropy` | Double | `3.5` | Minimum Shannon entropy for high-entropy secrets |
| `-MaxFileSizeMB` | Int | `10` | Maximum file size to scan (MB) |
| `-ContextLines` | Int | `2` | Number of context lines around findings |
| `-ThrottleLimit` | Int | `10` | Parallel processing threads (1-50) |
| `-ShowProgress` | Switch | `false` | Display real-time progress |
| `-ShowSecretValues` | Switch | `false` | Display actual secret values (DANGEROUS) |
| `-ScanGitHistory` | Switch | `false` | Scan git commit history |
| `-Interactive` | Switch | `false` | Enable interactive remediation mode |
| `-GenerateReport` | Switch | `false` | Generate comprehensive HTML report |
| `-FailOnCritical` | Switch | `false` | Exit with code 1 if Critical findings detected |
| `-QuietMode` | Switch | `false` | Suppress console output except errors |
| `-WhitelistFile` | String | `null` | Path to whitelist file |
| `-ConfigFile` | String | `null` | Path to YAML/JSON configuration file |
| `-ExcludeFolders` | String[] | See below | Folders to exclude |
| `-ExcludeFiles` | String[] | See below | File patterns to exclude |

### Default Exclusions

**Folders:** `.git`, `.svn`, `node_modules`, `bin`, `obj`, `.vs`, `.vscode`, `target`, `build`, `dist`, `vendor`, `__pycache__`, `.idea`, `bower_components`, `jspm_packages`, `.next`

**Files:** `*.min.js`, `*.min.css`, `*.map`, `*.dll`, `*.exe`, `*.zip`, `*.tar`, `*.gz`, `*.jpg`, `*.png`, `*.gif`, `*.pdf`, `*.woff*`, `*.ttf`, `*.eot`, `.env`

## 🔍 Detected Secret Types

### Cloud Providers
- **AWS Access Keys** - AKIA*, ASIA*, ABIA*, ACCA* patterns
- **AWS Secret Access Keys** - 40-character base64 encoded keys
- **AWS Session Tokens** - Temporary session credentials
- **Azure Storage Account Keys** - Connection strings with AccountKey
- **Azure SAS Tokens** - Shared Access Signatures
- **Google API Keys** - AIza* pattern keys
- **Google OAuth Client IDs** - *.apps.googleusercontent.com

### Version Control
- **GitHub Personal Access Tokens** - ghp_*, gho_*, ghu_*, ghs_*, ghr_*
- **GitHub OAuth Tokens** - 40-character hex tokens
- **GitLab Personal Access Tokens** - glpat-* pattern

### Payment Processors
- **Stripe Live API Keys** - sk_live_* (Critical severity)
- **Stripe Restricted Keys** - rk_live_*
- **Stripe Test Keys** - sk_test_*
- **Square Access Tokens** - sq0atp-* pattern
- **PayPal/Braintree Tokens** - Production access tokens

### Communication Services
- **Slack Tokens** - xox[baprs]-* pattern
- **Slack Webhooks** - hooks.slack.com URLs
- **Twilio API Keys** - SK* pattern (32 chars)
- **Twilio Account SIDs** - AC* pattern
- **SendGrid API Keys** - SG.*.* format
- **Mailgun API Keys** - key-* pattern
- **Mailchimp API Keys** - *-us[0-9]+ pattern

### Databases
- **MongoDB Connection Strings** - mongodb:// or mongodb+srv:// with credentials
- **MySQL Connection Strings** - mysql:// with username:password
- **PostgreSQL Connection Strings** - postgresql:// with credentials
- **SQL Server Connection Strings** - Server=*;Password=* format

### Development Tools
- **NPM Access Tokens** - npm_* pattern
- **Docker Registry Credentials** - docker_password/docker_token
- **Heroku API Keys** - UUID format keys

### Cryptographic Keys
- **PEM Private Keys** - -----BEGIN*PRIVATE KEY-----
- **RSA Private Keys** - -----BEGIN RSA PRIVATE KEY-----
- **SSH Private Keys** - -----BEGIN OPENSSH PRIVATE KEY-----
- **PGP Private Keys** - -----BEGIN PGP PRIVATE KEY BLOCK-----

### AI Services
- **OpenAI API Keys** - sk-proj-* or sk-* pattern (48 chars)

### Generic Patterns
- **JWT Tokens** - Three base64 sections separated by dots
- **Bearer Tokens** - Bearer authorization tokens
- **OAuth Tokens** - Generic OAuth access tokens
- **Basic Auth Credentials** - Base64 encoded credentials
- **High-Entropy API Keys** - Generic api_key/apikey patterns with high entropy
- **Generic Passwords** - password=* assignments
- **Generic Secrets** - secret/token/credential assignments

## 📚 Examples

### Example 1: Basic Project Scan
```powershell
.\find_secrets.ps1 -Directory "C:\Projects\MyApp"
```
Scans the entire MyApp directory with default settings.

### Example 2: CI/CD Pipeline Integration
```powershell
.\find_secrets.ps1 -Directory . -OutputFormat sarif -FailOnCritical -QuietMode
if ($LASTEXITCODE -ne 0) {
    Write-Error "Security scan failed!"
    exit 1
}
```
Runs silently in CI/CD, outputs SARIF format, and fails the build if critical findings are detected.

### Example 3: Comprehensive Audit with Report
```powershell
.\find_secrets.ps1 `
    -Directory "C:\Projects\MyApp" `
    -ScanGitHistory `
    -GenerateReport `
    -OutputFormat json `
    -MinSeverity Medium `
    -ShowProgress
```
Performs a thorough scan including git history, generates both JSON and HTML reports, only shows Medium+ severity, with progress updates.

### Example 4: Using Whitelist
```powershell
# Create whitelist file
@"
test_api_key_12345
example.com:dummy_password
config.js:placeholder_key
"@ | Out-File whitelist.txt

# Run scan with whitelist
.\find_secrets.ps1 -Directory . -WhitelistFile whitelist.txt
```
Creates a whitelist to exclude known test values and runs the scan.

### Example 5: Interactive Remediation
```powershell
.\find_secrets.ps1 -Directory . -Interactive -MinSeverity High
```
Scans for High and Critical findings, then enters interactive mode to review and remediate each finding.

### Example 6: Custom Exclusions
```powershell
.\find_secrets.ps1 `
    -Directory . `
    -ExcludeFolders @('test', 'mock', 'fixtures') `
    -ExcludeFiles @('*.test.js', '*.spec.ts') `
    -MinEntropy 4.0
```
Excludes test directories and files, with a higher entropy threshold.

## 📝 Whitelist Format

The whitelist file supports two formats:

```text
# Simple pattern matching (matches anywhere in findings)
test_api_key_12345
dummy_password
example_token

# File-specific patterns (file:pattern)
config.js:placeholder_key
test.py:mock_secret_value
src/utils/constants.ts:DEMO_API_KEY

# Comments start with #
# Blank lines are ignored
```

**Pattern Matching:**
- Simple patterns match if they appear anywhere in the matched text
- File-specific patterns only match in the specified file path
- Patterns are case-sensitive
- Use wildcards in file paths: `*/test/*:test_key`

## 📊 Output Formats

### Text (Default)
Human-readable console output with colored severity indicators and detailed information.

```
[2025-01-15 14:30:22] [CRITICAL] AWS Access Key ID | C:\config\aws.json:12 | Entropy: 4.32
  └─ Matched: AKIAIOSFOD***REDACTED***
```

### JSON
Machine-readable format for integration with other tools.

```json
{
  "Timestamp": "2025-01-15 14:30:22",
  "Category": "AWS Access Key ID",
  "Severity": "Critical",
  "Description": "AWS Access Key ID - grants access to AWS resources",
  "Remediation": "Rotate key immediately in AWS IAM. Use AWS Secrets Manager or environment variables.",
  "FilePath": "C:\\config\\aws.json",
  "LineNumber": 12,
  "ColumnStart": 245,
  "MatchedValue": "AKIAIOSFOD***REDACTED***",
  "Entropy": 4.32,
  "FileExtension": ".json",
  "FileSize": 1024
}
```

### CSV
Spreadsheet-compatible format for analysis in Excel or other tools.

| Timestamp | Severity | Category | FilePath | LineNumber | Entropy | MatchedValue |
|-----------|----------|----------|----------|------------|---------|--------------|
| 2025-01-15 14:30:22 | Critical | AWS Access Key ID | C:\config\aws.json | 12 | 4.32 | AKIAIOSFOD*** |

### HTML
Beautiful, interactive report with:
- Summary statistics dashboard with color-coded severity counts
- Individual finding cards with syntax highlighting
- Context lines showing surrounding code
- Remediation guidance for each finding
- Printable format
- Responsive design

### SARIF
Static Analysis Results Interchange Format - compatible with GitHub Code Scanning, Azure DevOps, and other security platforms.

```json
{
  "version": "2.1.0",
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Enterprise Secret Scanner",
          "version": "3.0"
        }
      },
      "results": [...]
    }
  ]
}
```

## 🚦 Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No secrets found - scan completed successfully |
| `1` | Secrets found - review required |
| `2` | Critical findings detected (only with `-FailOnCritical` flag) |
| `3` | Fatal error during execution |

## ⚡ Performance Considerations

### PowerShell 7+ (Recommended)
- **Parallel Processing:** Uses `-ThrottleLimit` parameter (default: 10 threads)
- **Speed:** 50-100 files/second on modern hardware
- **Memory:** Efficient with streaming
- **Best for:** Large codebases (1000+ files)

### PowerShell 5.1
- **Sequential Processing:** Single-threaded
- **Speed:** 20-40 files/second
- **Memory:** Lower memory footprint
- **Best for:** Smaller projects or environments without PS7+

### Git History Scanning
⚠️ **WARNING:** Can be very slow on large repositories
- Scans **every commit** in repository history
- Time scales with: number of commits × size of changes
- Typical performance: 10-100 commits/second
- **Recommendation:** Use sparingly or only in scheduled audits

### Performance Tips
```powershell
# Fast scan - skip git history, increase file size limit
.\find_secrets.ps1 -Directory . -MaxFileSizeMB 5

# Thorough but slow scan
.\find_secrets.ps1 -Directory . -ScanGitHistory -MaxFileSizeMB 20

# PowerShell 7 with maximum parallelization
pwsh -File find_secrets.ps1 -Directory . -ThrottleLimit 20
```

## 🔗 CI/CD Integration

### GitHub Actions
```yaml
name: Secret Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0  # Full history for git scanning
      
      - name: Run Secret Scanner
        run: |
          pwsh -File find_secrets.ps1 `
            -Directory . `
            -OutputFormat sarif `
            -FailOnCritical `
            -QuietMode
      
      - name: Upload SARIF Results
        if: always()
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: secret-scan.sarif
```

### Azure DevOps
```yaml
trigger:
  - main
  - develop

pool:
  vmImage: 'windows-latest'

steps:
  - checkout: self
    fetchDepth: 0

  - task: PowerShell@2
    displayName: 'Scan for Secrets'
    inputs:
      filePath: 'find_secrets.ps1'
      arguments: >
        -Directory $(Build.SourcesDirectory)
        -OutputFormat json
        -FailOnCritical
        -GenerateReport
      failOnStderr: true

  - task: PublishBuildArtifacts@1
    displayName: 'Publish Scan Report'
    condition: always()
    inputs:
      PathtoPublish: 'secret-scan.html'
      ArtifactName: 'SecurityScanReport'
```

### Jenkins
```groovy
pipeline {
    agent { label 'windows' }
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        
        stage('Secret Scan') {
            steps {
                powershell '''
                    ./find_secrets.ps1 `
                        -Directory . `
                        -OutputFormat json `
                        -GenerateReport `
                        -FailOnCritical
                '''
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: 'secret-scan.*', allowEmptyArchive: true
        }
        failure {
            emailext (
                subject: "Secret Scan Failed: ${env.JOB_NAME}",
                body: "Critical secrets detected in build ${env.BUILD_NUMBER}",
                to: 'security@company.com'
            )
        }
    }
}
```

### GitLab CI
```yaml
secret_scan:
  stage: security
  image: mcr.microsoft.com/powershell:latest
  script:
    - pwsh -File find_secrets.ps1 -Directory . -OutputFormat json -FailOnCritical
  artifacts:
    reports:
      sast: secret-scan.sarif
    paths:
      - secret-scan.*
    expire_in: 30 days
  only:
    - merge_requests
    - main
```

## ✅ Best Practices

### 1. Pre-Commit Hooks
Prevent secrets from being committed in the first place:

```powershell
# .git/hooks/pre-commit
#!/usr/bin/env pwsh
.\find_secrets.ps1 -Directory . -MinSeverity High -QuietMode
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Commit rejected: Secrets detected!" -ForegroundColor Red
    exit 1
}
```

### 2. Integrate in CI/CD Pipeline
```powershell
# Fail builds on Critical findings
.\find_secrets.ps1 -Directory . -FailOnCritical -OutputFormat sarif
```

### 3. Regular Security Audits
```powershell
# Weekly comprehensive scan with git history
.\find_secrets.ps1 -Directory . -ScanGitHistory -GenerateReport -MinSeverity Medium
```

### 4. Use Whitelists Judiciously
```text
# Document why items are whitelisted
# whitelist.txt

# Test fixtures - approved by security team 2025-01-15
test/fixtures/:dummy_api_key_for_testing

# Demo constants - public documentation
docs/examples/:EXAMPLE_TOKEN_DO_NOT_USE
```

### 5. Immediate Remediation Steps
When secrets are detected:
1. **Rotate credentials immediately** - Don't wait
2. **Remove from code** - Use environment variables or secrets manager
3. **Clean git history** - Use BFG Repo-Cleaner or git-filter-branch
4. **Review access logs** - Check if credentials were compromised
5. **Update documentation** - Ensure team knows proper practices

### 6. Use Proper Secrets Management
```powershell
# ❌ Bad - Hardcoded secret
$apiKey = "sk_live_abc123xyz789"

# ✅ Good - Environment variable
$apiKey = $env:STRIPE_API_KEY

# ✅ Better - Azure Key Vault
$apiKey = Get-AzKeyVaultSecret -VaultName "MyVault" -Name "StripeApiKey"
```

### 7. Never Use `-ShowSecretValues` in Production
```powershell
# ❌ Dangerous - exposes secrets in logs
.\find_secrets.ps1 -Directory . -ShowSecretValues

# ✅ Safe - secrets are redacted
.\find_secrets.ps1 -Directory .
```

### 8. Layer Security Controls
- **Prevention:** Pre-commit hooks
- **Detection:** CI/CD scanning
- **Audit:** Scheduled comprehensive scans
- **Response:** Automated rotation procedures

## 🐛 Troubleshooting

### "Execution Policy" Error
**Problem:** Script cannot run due to PowerShell execution policy.

**Solution:**
```powershell
# Option 1: Set for current user (recommended)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Option 2: Bypass for single execution
powershell -ExecutionPolicy Bypass -File find_secrets.ps1 -Directory .

# Option 3: Unblock the downloaded file
Unblock-File -Path find_secrets.ps1
```

### Out of Memory Errors
**Problem:** Scanner runs out of memory on large repositories.

**Solution:**
```powershell
# Reduce maximum file size
.\find_secrets.ps1 -Directory . -MaxFileSizeMB 5

# Exclude large directories
.\find_secrets.ps1 -Directory . -ExcludeFolders @('node_modules', 'build', 'dist')

# Scan in chunks
.\find_secrets.ps1 -Directory .\src
.\find_secrets.ps1 -Directory .\lib
```

### Slow Git History Scanning
**Problem:** `-ScanGitHistory` takes too long.

**Solution:**
```powershell
# Scan recent commits only (manual approach)
git log --since="2024-01-01" --pretty=format:"%H" | ForEach-Object {
    git show $_
} | Select-String -Pattern "AKIA[0-9A-Z]{16}"

# Or skip git history scanning
.\find_secrets.ps1 -Directory . # Don't use -ScanGitHistory

# Or run git history scan separately on schedule
```

### Too Many False Positives
**Problem:** Scanner reports many test values or examples.

**Solutions:**
```powershell
# 1. Increase entropy threshold
.\find_secrets.ps1 -Directory . -MinEntropy 4.5

# 2. Use whitelist file
.\find_secrets.ps1 -Directory . -WhitelistFile whitelist.txt

# 3. Increase minimum severity
.\find_secrets.ps1 -Directory . -MinSeverity High

# 4. Exclude test directories
.\find_secrets.ps1 -Directory . -ExcludeFolders @('test', 'tests', '__tests__', 'spec')
```

### Git Not Found (for Git History Scan)
**Problem:** Git is not installed or not in PATH.

**Solution:**
```powershell
# Install Git
winget install Git.Git

# Or verify PATH
$env:PATH -split ';' | Select-String git

# Or skip git scanning
.\find_secrets.ps1 -Directory . # Omit -ScanGitHistory
```

### Access Denied Errors
**Problem:** Cannot read certain files or directories.

**Solution:**
```powershell
# Run as Administrator
Start-Process pwsh -Verb RunAs -ArgumentList "-File find_secrets.ps1 -Directory ."

# Or exclude inaccessible directories
.\find_secrets.ps1 -Directory . -ExcludeFolders @('System Volume Information', '$RECYCLE.BIN')
```

## ⚠️ Limitations

### Known Limitations
1. **Encrypted Secrets:** Cannot detect secrets that are encrypted in code
2. **Encoded Secrets:** May miss base64, hex, or custom-encoded secrets
3. **Dynamic Secrets:** Cannot detect secrets generated at runtime
4. **Obfuscated Code:** Limited detection in heavily obfuscated code
5. **Binary Files:** Cannot scan compiled binaries or archives
6. **Performance:** Git history scanning scales poorly with repository size
7. **False Positives:** Test data and examples may trigger detections
8. **Platform:** Windows-only (PowerShell dependency)

### Not a Replacement For
- **Proper Secrets Management** - Use Azure Key Vault, AWS Secrets Manager, HashiCorp Vault
- **Security Audits** - Human review is still essential
- **Access Controls** - Implement least-privilege access
- **Monitoring** - Use runtime secret detection and anomaly detection
- **Training** - Educate developers on secure coding practices

## 🤝 Contributing

Contributions are welcome! Here's how to contribute:

### Adding New Secret Patterns
```powershell
# In the $script:SecretPatterns hashtable, add:
'New Service API Key' = @{
    Patterns = @('service_[a-zA-Z0-9]{32}')
    Severity = 'High'
    Description = 'New Service API Key'
    Remediation = 'Rotate key in service dashboard.'
    Entropy = $false
    FalsePositiveKeywords = @('example', 'test')
}
```

### Testing Requirements
- Test on Windows PowerShell 5.1
- Test on PowerShell 7+
- Verify no false positives on common test patterns
- Ensure performance is acceptable

### Pull Request Guidelines
1. Fork the repository
2. Create a feature branch
3. Add tests for new patterns
4. Update documentation
5. Submit pull request with clear description

## 📄 License

[Your License Here - e.g., MIT, Apache 2.0, GPL]

## 🔐 Security Reporting

If you discover a security vulnerability in this tool, please email:
**security@yourcompany.com**

Do not open public issues for security vulnerabilities.

## 📞 Support

- **Issues:** [GitHub Issues](https://github.com/yourorg/secret-scanner/issues)
- **Discussions:** [GitHub Discussions](https://github.com/yourorg/secret-scanner/discussions)
- **Email:** support@yourcompany.com

## 📋 Changelog

### v3.0 (Current - 2025-01-15)
- ✨ Added 50+ secret detection patterns
- ⚡ Parallel processing support (PowerShell 7+)
- 🎯 Interactive remediation mode
- 📊 HTML report generation with charts
- 📋 SARIF output format for GitHub Code Scanning
- 🔍 Git history scanning capability
- 🧮 Shannon entropy-based detection
- 📝 Comprehensive logging system
- 🎨 Beautiful console output with colors
- ⚙️ Configurable severity levels
- 📁 Whitelist support
- 🔧 Context line display
- 🚀 Performance optimizations

### Future Roadmap
- Configuration file support (YAML/JSON)
- Custom pattern definitions
- Machine learning-based detection
- Linux/macOS support via PowerShell Core
- Database scanning
- Memory scanning
- Container image scanning
- Kubernetes secret scanning

---

**⚠️ IMPORTANT DISCLAIMER**

This tool helps detect secrets but is not foolproof. It should be used as **one layer** of a comprehensive security strategy. Always:

- Use proper secrets management solutions
- Never commit secrets to version control
- Rotate credentials immediately if exposed
- Implement defense-in-depth security practices
- Conduct regular security audits
- Train developers on secure coding practices

**The tool's authors are not responsible for any security breaches or damages resulting from the use or misuse of this tool.**

---

Made with ❤️ for better security practices
