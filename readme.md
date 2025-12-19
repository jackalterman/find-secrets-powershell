# Enterprise Secret Scanner

A comprehensive, enterprise-grade PowerShell tool for detecting secrets, credentials, API keys, and other sensitive information in your codebase and git history. This scanner is built for performance, with features like parallel processing, file caching, and adaptive throttling to ensure fast and efficient scans, even on large projects.

## Features

### Core Capabilities
- **Comprehensive Detection**: 50+ pre-defined patterns for detecting AWS keys, GitHub tokens, API keys, private keys, database credentials, and more.
- **Entropy Analysis**: Uses Shannon entropy calculation to identify high-entropy strings that are likely to be secrets.
- **Git History Scanning**: Scans entire commit history to find secrets that may have been removed from the current code but still exist in history.
- **Multi-format Output**: Export results as text, JSON, CSV, HTML, or SARIF for integration with other tools and platforms.
- **Interactive Remediation**: Step through findings one-by-one with guided remediation actions.
- **Whitelist Support**: Exclude known false positives using simple patterns or file-specific rules.
- **Context Display**: Shows surrounding code lines for better context on each finding.
- **Comprehensive Reporting**: Generate beautiful, detailed HTML reports with statistics and charts.

### Performance & Optimization
- **High-Speed Parallel Processing**: Utilizes multi-threaded scanning in PowerShell 7+ for maximum speed.
- **File Caching**: Dramatically speeds up subsequent scans by caching results and only scanning new or changed files.
- **Adaptive Throttling**: Automatically adjusts the number of parallel threads based on system resources (CPU cores) to optimize performance without overloading your system.
- **Memory Management**: Includes memory monitoring and recommendations to ensure stability on large scans.

### Security & Usability
- **Safe by Default**: Secret values are redacted in output by default to prevent accidental exposure.
- **False Positive Reduction**: Uses keyword matching to reduce noise from test data and examples.
- **Configurable Severity Levels**: Filter findings by severity (Critical, High, Medium, Low).
- **Extensive File Support**: Scans over 60 different file extensions by default.
- **CI/CD Friendly**: Designed for easy integration into CI/CD pipelines with features like `-FailOnCritical` and `-QuietMode`.

## Requirements

- **Windows PowerShell 5.1** (for basic sequential scanning) or **PowerShell 7+** (recommended, for parallel processing and performance features).
- **Windows Operating System** (for local use). The script is cross-platform with PowerShell 7 but is primarily developed and tested on Windows.
- **Git** (optional, only required for the `-ScanGitHistory` feature).

## Installation

No complex installation is required. Simply clone the repository which includes the main script and the necessary performance modules.

```powershell
# Clone the repository
git clone https://github.com/your-repo/find-secrets-powershell.git
cd find-secrets-powershell
```

The directory structure includes the main `find_secrets.ps1` script and a `modules` folder containing the performance optimization modules. These modules are loaded automatically by the main script.

## Quick Start

```powershell
# Basic scan of the current directory
.\find_secrets.ps1 -Directory .

# Fast subsequent scan using the file cache
.\find_secrets.ps1 -Directory . -UseCache

# Scan with a detailed HTML report
.\find_secrets.ps1 -Directory "C:\MyProject" -GenerateReport

# Scan git history (WARNING: can be slow on large repos)
.\find_secrets.ps1 -Directory . -ScanGitHistory

# CI/CD: Scan for high-severity findings and fail the build if any are found
.\find_secrets.ps1 -Directory . -MinSeverity High -FailOnCritical -QuietMode
```

## Usage

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-Directory` | String | *Required* | Root directory to scan. |
| `-UseCache` | Switch | `false` | Enable file caching to speed up subsequent scans by only scanning new or changed files. |
| `-CacheDirectory` | String | `.secret-scanner-cache` | Directory to store cache files. |
| `-OutputFormat` | String | `text` | Output format: `text`, `json`, `csv`, `html`, `sarif`. |
| `-LogFile` | String | `secret-scan-TIMESTAMP.log` | Path for the detailed log file. |
| `-MinSeverity` | String | `Low` | Minimum severity to report: `Low`, `Medium`, `High`, `Critical`. |
| `-MinEntropy` | Double | `3.5` | Minimum Shannon entropy for a string to be considered a high-entropy secret. |
| `-MaxFileSizeMB` | Int | `10` | Maximum file size to scan (in MB). |
| `-ContextLines` | Int | `2` | Number of context lines to show around each finding. |
| `-ThrottleLimit` | Int | `10` | Number of parallel threads for scanning (1-50, PowerShell 7+ only). |
| `-ShowProgress` | Switch | `false` | Display real-time progress information. |
| `-ShowSecretValues`| Switch | `false` | **(DANGEROUS)** Display actual secret values in the output. Use only for debugging. |
| `-ScanGitHistory` | Switch | `false` | Scan the entire git commit history for secrets. Can be very slow. |
| `-Interactive`| Switch | `false` | Enable interactive mode to review and remediate each finding. |
| `-GenerateReport`| Switch | `false` | Generate a comprehensive HTML report. |
| `-FailOnCritical`| Switch | `false` | Exit with a non-zero exit code if any Critical findings are detected. |
| `-QuietMode` | Switch | `false` | Suppress all console output except for fatal errors. |
| `-WhitelistFile`| String | `null` | Path to a whitelist file containing patterns to ignore. |
| `-ConfigFile` | String | `null` | (Future Use) Path to a YAML/JSON configuration file. |
| `-ExcludeFolders`| String[] | *(see defaults)* | Array of folder names to exclude from the scan. |
| `-ExcludeFiles` | String[] | *(see defaults)* | Array of file name patterns to exclude from the scan. |

### Default Exclusions

**Folders:** `.git`, `.svn`, `node_modules`, `bin`, `obj`, `.vs`, `.vscode`, `target`, `build`, `dist`, `vendor`, `__pycache__`, `.idea`, `bower_components`, `jspm_packages`, `.next`

**Files:** `*.min.js`, `*.min.css`, `*.map`, `*.dll`, `*.exe`, `*.zip`, `*.tar`, `*.gz`, `*.jpg`, `*.png`, `*.gif`, `*.pdf`, `*.woff*`, `*.ttf`, `*.eot`, `.env`

## Performance Optimizations

The script includes several features to improve performance, especially on large codebases. These are enabled automatically when using PowerShell 7+.

### File Caching

- **How it works**: When you run a scan with the `-UseCache` switch, the script creates a cache of metadata for every file it scans (hash, size, last modified date). On subsequent scans, it quickly checks this cache and only scans files that are new or have been modified.
- **Benefit**: This can reduce scan times by over 90% on projects where only a few files change between scans.
- **Usage**:
  ```powershell
  # First scan, creates the cache
  .\find_secrets.ps1 -Directory . -UseCache

  # Second scan, much faster
  .\find_secrets.ps1 -Directory . -UseCache
  ```
- **Cache Location**: By default, the cache is stored in a `.secret-scanner-cache` directory. You can change this with the `-CacheDirectory` parameter.

### Adaptive Parallel Processing

- **How it works**: On PowerShell 7+, the script scans files in parallel. It automatically detects the number of available CPU cores and adjusts its `-ThrottleLimit` to an optimal level, preventing it from overwhelming your system while maximizing speed. You can always manually override this with the `-ThrottleLimit` parameter.
- **Benefit**: Significantly faster scan times compared to sequential scanning. A scan that might take minutes in PowerShell 5.1 can complete in seconds.

### Memory Management

- **How it works**: Before starting a large scan, the script provides recommendations if it estimates that memory usage might be high based on the number of files and average file size. It also reports peak memory usage in the final summary.
- **Benefit**: Helps prevent out-of-memory errors on very large projects and provides insights into the resource consumption of the scan.

## Examples

### Example 1: Fast Incremental Scans in a Dev Workflow
A developer can run fast, incremental scans after making changes.

```powershell
# Run a quick scan on your project, subsequent runs will be much faster
.\find_secrets.ps1 -Directory "C:\Projects\MyWebApp" -UseCache -MinSeverity High
```

### Example 2: Comprehensive CI/CD Pipeline Scan
Integrate the scanner into your CI/CD pipeline to automatically fail builds on critical findings and generate reports.

```powershell
# This command is ideal for a CI/CD script
.\find_secrets.ps1 `
    -Directory . `
    -OutputFormat sarif `
    -FailOnCritical `
    -QuietMode `
    -UseCache # Use caching to keep pipeline runs fast
```
If critical secrets are found, the script will exit with a non-zero exit code, failing the pipeline step. The `secret-scan.sarif` file can then be uploaded to GitHub Code Scanning or other security dashboards.

### Example 3: Deep Audit with Git History and HTML Report
Perform a deep, one-time audit on a repository.

```powershell
.\find_secrets.ps1 `
    -Directory "C:\Projects\LegacyApp" `
    -ScanGitHistory `
    -GenerateReport `
    -OutputFormat json `
    -MinSeverity Medium `
    -ShowProgress
```
This performs a thorough scan including the full git history, generates both JSON and a detailed HTML report, only shows Medium+ severity findings, and displays real-time progress.

### Example 4: Using a Whitelist for False Positives
If you have known, non-sensitive strings that are being flagged, use a whitelist.

```powershell
# Create a whitelist.txt file
@"
# This is a known test key for our mock server
d9a8a7a6-a5b4-4a3c-80f0-c5e3a2b1c0d1

# Ignore placeholder values in config files
config.example.js:YOUR_API_KEY_HERE
"@ | Out-File whitelist.txt

# Run the scan with the whitelist
.\find_secrets.ps1 -Directory . -WhitelistFile .\whitelist.txt
```

## Troubleshooting

### "Execution Policy" Error
**Problem:** The script cannot run due to PowerShell's security restrictions.
**Solution:** Run one of the following commands.
```powershell
# Option 1: Bypass for a single execution (Recommended)
powershell -ExecutionPolicy Bypass -File .\find_secrets.ps1 -Directory .

# Option 2: Set policy for the current user
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Modules Not Loading
**Problem:** The script reports "Failed to load performance modules".
**Solution:** Ensure the `modules` directory with the `.psm1` files is in the same directory as `find_secrets.ps1`. The script relies on these modules for caching and parallel processing. If they are missing, it will fall back to slower, sequential scanning.

### Out of Memory Errors
**Problem:** The scanner fails on very large repositories.
**Solution:**
```powershell
# 1. Reduce the throttle limit to use fewer parallel threads
.\find_secrets.ps1 -Directory . -ThrottleLimit 4

# 2. Reduce the maximum file size to scan
.\find_secrets.ps1 -Directory . -MaxFileSizeMB 5

# 3. Exclude large, non-source-code directories
.\find_secrets.ps1 -Directory . -ExcludeFolders @('assets', 'vendor', 'third-party')
```
---

**IMPORTANT DISCLAIMER**

This tool helps detect secrets but is not foolproof. It should be used as **one layer** of a comprehensive security strategy. Always use proper secrets management solutions (like Azure Key Vault, AWS Secrets Manager, or HashiCorp Vault) and never commit secrets to version control.
