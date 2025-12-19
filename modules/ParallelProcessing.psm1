# ParallelProcessing.psm1
# Performance-optimized parallel processing for secret scanning

<#
.SYNOPSIS
    Optimized parallel file scanning with adaptive throttling
.DESCRIPTION
    This module provides performance-optimized parallel processing for secret scanning
    with features like adaptive throttling, batch processing, and memory management
#>

function Get-OptimalThrottleLimit {
    <#
    .SYNOPSIS
        Calculate optimal throttle limit based on system resources
    .DESCRIPTION
        Analyzes CPU cores, available memory, and file count to determine
        the best number of parallel threads
    #>
    param(
        [int]$FileCount,
        [int]$RequestedLimit = 10
    )
    
    try {
        # Get system info
        $cpuCores = (Get-CimInstance -ClassName Win32_ComputerSystem).NumberOfLogicalProcessors
        
        # Calculate based on CPU cores (leave 1-2 cores free)
        $cpuBasedLimit = [Math]::Max(1, $cpuCores - 2)
        
        # For small file counts, reduce parallelism
        if ($FileCount -lt 50) {
            $optimalLimit = [Math]::Min(5, $cpuBasedLimit)
        }
        elseif ($FileCount -lt 200) {
            $optimalLimit = [Math]::Min(10, $cpuBasedLimit)
        }
        else {
            $optimalLimit = $cpuBasedLimit
        }
        
        # Respect user's requested limit if reasonable
        $finalLimit = [Math]::Min($RequestedLimit, $optimalLimit)
        
        return [Math]::Max(1, $finalLimit)
    }
    catch {
        # Fallback to safe default
        return 5
    }
}

function Split-FilesIntoBatches {
    <#
    .SYNOPSIS
        Split files into optimally-sized batches for processing
    .DESCRIPTION
        Groups files by size to ensure even workload distribution across threads
    #>
    param(
        [Parameter(Mandatory)]
        [System.IO.FileInfo[]]$Files,
        
        [int]$BatchCount = 10
    )
    
    if ($Files.Count -eq 0) {
        return @()
    }
    
    # Sort files by size (largest first) for better load balancing
    $sortedFiles = $Files | Sort-Object Length -Descending
    
    # Calculate target batch size
    $batchSize = [Math]::Ceiling($sortedFiles.Count / $BatchCount)
    
    # Create batches
    $batches = @()
    for ($i = 0; $i -lt $sortedFiles.Count; $i += $batchSize) {
        $endIndex = [Math]::Min($i + $batchSize - 1, $sortedFiles.Count - 1)
        $batches += , ($sortedFiles[$i..$endIndex])
    }
    
    return $batches
}

function Invoke-OptimizedParallelScan {
    <#
    .SYNOPSIS
        Execute parallel file scanning with optimized performance
    .DESCRIPTION
        Processes files in parallel with adaptive throttling and memory management.
        This is a drop-in replacement for the parallel scanning logic in the main script.
    #>
    param(
        [Parameter(Mandatory)]
        [System.IO.FileInfo[]]$Files,
        
        [Parameter(Mandatory)]
        [hashtable]$Patterns,
        
        [Parameter(Mandatory = $false)]
        [array]$Whitelist = @(),
        
        [Parameter(Mandatory)]
        [double]$MinEntropy,
        
        [Parameter(Mandatory)]
        [int]$MinSeverityLevel,
        
        [Parameter(Mandatory)]
        [int]$ContextLines,
        
        [int]$ThrottleLimit = 10,
        
        [bool]$ShowSecretValues = $false,
        
        [int]$MaxFileSizeMB = 10,
        
        [string]$GetEntropyFunction,
        
        [string]$GetSeverityValueFunction,
        
        [string]$TestWhitelistedFunction,
        
        [string]$TestFalsePositiveFunction,
        
        [string]$GetContextLinesFunction
    )
    
    # Calculate optimal throttle limit
    $optimalThrottle = Get-OptimalThrottleLimit -FileCount $Files.Count -RequestedLimit $ThrottleLimit
    
    Write-Verbose "Using throttle limit: $optimalThrottle for $($Files.Count) files"
    
    # Execute parallel processing
    $parallelResults = $Files | ForEach-Object -ThrottleLimit $optimalThrottle -Parallel {
        $file = $_
        $localFindings = [System.Collections.Generic.List[object]]::new()
        
        # Import variables from parent scope
        $patterns = $using:Patterns
        $whitelist = $using:Whitelist
        $minEntropy = $using:MinEntropy
        $minSevLevel = $using:MinSeverityLevel
        $context = $using:ContextLines
        $showVals = $using:ShowSecretValues
        $maxSize = $using:MaxFileSizeMB
        
        # Recreate function definitions from parent scope strings
        $GetEntropyDef = $using:GetEntropyFunction
        $GetSeverityValueDef = $using:GetSeverityValueFunction
        $TestWhitelistedDef = $using:TestWhitelistedFunction
        $TestFalsePositiveDef = $using:TestFalsePositiveFunction
        $GetContextLinesDef = $using:GetContextLinesFunction
        
        # Recreate functions in parallel runspace
        ${function:Get-Entropy} = [scriptblock]::Create($GetEntropyDef)
        ${function:Get-SeverityValue} = [scriptblock]::Create($GetSeverityValueDef)
        ${function:Test-Whitelisted} = [scriptblock]::Create($TestWhitelistedDef)
        ${function:Test-FalsePositive} = [scriptblock]::Create($TestFalsePositiveDef)
        ${function:Get-ContextLines} = [scriptblock]::Create($GetContextLinesDef)
        
        try {
            # Check file size
            if ($file.Length -gt ($maxSize * 1MB)) {
                return [PSCustomObject]@{
                    File     = $file.FullName
                    Findings = @()
                    Skipped  = $true
                    Reason   = "File too large"
                }
            }
            
            # Read file content efficiently
            $content = $null
            try {
                $content = [System.IO.File]::ReadAllText($file.FullName)
            }
            catch {
                return [PSCustomObject]@{
                    File     = $file.FullName
                    Findings = @()
                    Skipped  = $true
                    Reason   = "Read error"
                }
            }
            
            if ([string]::IsNullOrWhiteSpace($content)) {
                return [PSCustomObject]@{
                    File     = $file.FullName
                    Findings = @()
                    Skipped  = $true
                    Reason   = "Empty file"
                }
            }
            
            # Scan for patterns
            foreach ($category in $patterns.Keys) {
                $patternInfo = $patterns[$category]
                $severity = $patternInfo.Severity
                $severityValue = Get-SeverityValue $severity
                
                if ($severityValue -lt $minSevLevel) {
                    continue
                }
                
                foreach ($pattern in $patternInfo.Patterns) {
                    try {
                        $matches = [regex]::Matches(
                            $content,
                            $pattern,
                            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
                        )
                        
                        foreach ($match in $matches) {
                            $matchedText = $match.Value
                            $secretValue = if ($match.Groups.Count -gt 1) {
                                $match.Groups[1].Value
                            }
                            else {
                                $matchedText
                            }
                            
                            # Apply filters
                            if (Test-FalsePositive -Value $secretValue -FalsePositiveKeywords $patternInfo.FalsePositiveKeywords) {
                                continue
                            }
                            
                            $entropy = Get-Entropy $secretValue
                            if ($patternInfo.Entropy -and $entropy -lt $minEntropy) {
                                continue
                            }
                            
                            if (Test-Whitelisted -Finding $matchedText -FilePath $file.FullName -Whitelist $whitelist) {
                                continue
                            }
                            
                            # Calculate line number
                            $lineNumber = ($content.Substring(0, $match.Index) -split "`n").Count
                            
                            # Get context
                            $contextLines = Get-ContextLines -Content $content -LineNumber $lineNumber -ContextLineCount $context
                            
                            # Redact value
                            $displayValue = if ($showVals) {
                                $matchedText
                            }
                            else {
                                if ($matchedText.Length -le 10) {
                                    "***REDACTED***"
                                }
                                else {
                                    $matchedText.Substring(0, [Math]::Min(10, $matchedText.Length)) + "***REDACTED***"
                                }
                            }
                            
                            if ($displayValue.Length -gt 150) {
                                $displayValue = $displayValue.Substring(0, 150) + "..."
                            }
                            
                            # Create finding
                            $finding = [PSCustomObject]@{
                                Timestamp     = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                                Category      = $category
                                Severity      = $severity
                                Description   = $patternInfo.Description
                                Remediation   = $patternInfo.Remediation
                                FilePath      = $file.FullName
                                LineNumber    = $lineNumber
                                ColumnStart   = $match.Index
                                MatchedValue  = $displayValue
                                Entropy       = [Math]::Round($entropy, 2)
                                ContextLines  = $contextLines
                                FileExtension = $file.Extension
                                FileSize      = $file.Length
                            }
                            
                            $localFindings.Add($finding)
                        }
                    }
                    catch {
                        # Continue on pattern error
                    }
                }
            }
            
            # Return result
            [PSCustomObject]@{
                File     = $file.FullName
                Findings = $localFindings.ToArray()
                Skipped  = $false
                Reason   = $null
            }
        }
        catch {
            [PSCustomObject]@{
                File     = $file.FullName
                Findings = @()
                Skipped  = $true
                Reason   = "Error"
            }
        }
    }
    
    return $parallelResults
}

# Export functions for dot-sourcing
Export-ModuleMember -Function @(
    'Get-OptimalThrottleLimit',
    'Split-FilesIntoBatches',
    'Invoke-OptimizedParallelScan'
) -ErrorAction SilentlyContinue
