# FileCache.psm1
# File caching for secret scanning optimization

<#
.SYNOPSIS
    Manages a file-based cache for scan results.
.DESCRIPTION
    This module provides functions to initialize, update, and optimize a file cache.
    The cache stores file metadata (hash, size, last write time) and flags if a
    file previously contained findings, allowing the scanner to skip unchanged files.
#>

function Initialize-ScanCache {
    <#
    .SYNOPSIS
        Initializes or loads a scan cache.
    .DESCRIPTION
        Checks for an existing cache file. If found, loads it. Otherwise,
        creates an empty cache.
    .PARAMETER CacheDirectory
        The directory where the cache file should be stored.
    .RETURNS
        A hashtable representing the cache.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$CacheDirectory
    )

    $cacheFilePath = Join-Path $CacheDirectory "scan_cache.json"
    $cache = @{}

    if (Test-Path $cacheFilePath) {
        try {
            $cacheContent = Get-Content -Path $cacheFilePath -Raw -ErrorAction Stop
            $cache = $cacheContent | ConvertFrom-Json -AsHashtable
            Write-Verbose "Cache loaded from $cacheFilePath"
        }
        catch {
            Write-Warning "Failed to load cache from $cacheFilePath: $($_.Exception.Message). Creating new cache."
            $cache = @{}
        }
    }
    else {
        # Ensure cache directory exists
        if (-not (Test-Path $CacheDirectory)) {
            New-Item -ItemType Directory -Path $CacheDirectory -Force | Out-Null
        }
        Write-Verbose "New cache initialized at $CacheDirectory"
    }
    return $cache
}

function Save-ScanCache {
    <#
    .SYNOPSIS
        Saves the current state of the scan cache to disk.
    .DESCRIPTION
        Serializes the cache hashtable to a JSON file.
    .PARAMETER Cache
        The cache hashtable to save.
    #>
    param(
        [Parameter(Mandatory)]
        [hashtable]$Cache
    )

    $cacheDirectory = Split-Path $Cache.CacheFilePath # Assuming CacheFilePath exists or can be derived
    if (-not (Test-Path $cacheDirectory)) {
        # This shouldn't happen if Initialize-ScanCache was called, but for robustness
        New-Item -ItemType Directory -Path $cacheDirectory -Force | Out-Null
    }

    $cacheFilePath = Join-Path $cacheDirectory "scan_cache.json"
    try {
        $Cache | ConvertTo-Json -Depth 100 | Set-Content -Path $cacheFilePath -Encoding UTF8 -ErrorAction Stop
        Write-Verbose "Cache saved to $cacheFilePath"
    }
    catch {
        Write-Warning "Failed to save cache to $cacheFilePath: $($_.Exception.Message)"
    }
}

function Get-FileHash {
    <#
    .SYNOPSIS
        Calculates the SHA256 hash of a file.
    .DESCRIPTION
        Reads a file and returns its SHA256 hash.
    .PARAMETER FilePath
        The full path to the file.
    .RETURNS
        The SHA256 hash as a string.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$FilePath
    )
    (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash
}

function Test-FileChanged {
    <#
    .SYNOPSIS
        Checks if a file has changed since it was last cached.
    .DESCRIPTION
        Compares current file's hash, size, and last write time with cached metadata.
    .PARAMETER File
        A System.IO.FileInfo object for the file to check.
    .PARAMETER Cache
        The scan cache hashtable.
    .RETURNS
        $true if the file has changed or is new, $false otherwise.
    #>
    param(
        [Parameter(Mandatory)]
        [System.IO.FileInfo]$File,
        [Parameter(Mandatory)]
        [hashtable]$Cache
    )

    $cacheEntry = $Cache[$File.FullName]

    if (-not $cacheEntry) {
        # File is new or not in cache, needs scanning
        Write-Verbose "File '$($File.Name)' is new or not in cache."
        return $true
    }

    # Check last write time first (fastest check)
    if ($File.LastWriteTimeUtc -gt $cacheEntry.LastWriteTimeUtc) {
        Write-Verbose "File '$($File.Name)' last write time changed."
        return $true
    }

    # Check size
    if ($File.Length -ne $cacheEntry.Length) {
        Write-Verbose "File '$($File.Name)' size changed."
        return $true
    }

    # Fallback to hash check if time and size are same (more robust but slower)
    # This might be optimized by only doing it for files that previously had findings
    if ($cacheEntry.HasFindings -and (Get-FileHash -FilePath $File.FullName) -ne $cacheEntry.Hash) {
        Write-Verbose "File '$($File.Name)' hash changed and previously had findings."
        return $true
    }
    
    # If file has no findings and hasn't changed by time/size, no need to re-scan
    if (-not $cacheEntry.HasFindings -and $File.LastWriteTimeUtc -eq $cacheEntry.LastWriteTimeUtc -and $File.Length -eq $cacheEntry.Length) {
        Write-Verbose "File '$($File.Name)' is unchanged and had no prior findings."
        return $false
    }
    
    # If the file had findings, and time/size are same, but hash wasn't checked, it's safer to re-scan
    # Or just return false and assume hash check would catch if HasFindings was true
    Write-Verbose "File '$($File.Name)' is unchanged based on metadata."
    return $false # File hasn't changed enough to warrant re-scan

}

function Update-FileCache {
    <#
    .SYNOPSIS
        Updates a file's entry in the cache.
    .DESCRIPTION
        Stores or updates file metadata, including hash, size, last write time,
        and whether it contained any findings.
    .PARAMETER File
        A System.IO.FileInfo object for the file.
    .PARAMETER Cache
        The scan cache hashtable.
    .PARAMETER FindingsCount
        The number of findings found in the file during the current scan.
    .PARAMETER FindingCategories
        An array of categories of findings found in the file.
    #>
    param(
        [Parameter(Mandatory)]
        [System.IO.FileInfo]$File,
        [Parameter(Mandatory)]
        [hashtable]$Cache,
        [Parameter(Mandatory)]
        [int]$FindingsCount,
        [Parameter(Mandatory)]
        [string[]]$FindingCategories = @()
    )

    $cacheEntry = @{
        Path = $File.FullName
        Hash = Get-FileHash -FilePath $File.FullName
        Length = $File.Length
        LastWriteTimeUtc = $File.LastWriteTimeUtc
        HasFindings = ($FindingsCount -gt 0)
        FindingsLastScan = $FindingsCount
        FindingCategories = $FindingCategories
    }
    $Cache[$File.FullName] = $cacheEntry
    Write-Verbose "Cache updated for '$($File.Name)' (Findings: $FindingsCount)"
}

function Get-CacheStatistics {
    <#
    .SYNOPSIS
        Provides statistics about the current cache.
    .DESCRIPTION
        Returns the total number of cached files and files with findings.
    .PARAMETER Cache
        The scan cache hashtable.
    .RETURNS
        A PSCustomObject with TotalCachedFiles and FilesWithFindings properties.
    #>
    param(
        [Parameter(Mandatory)]
        [hashtable]$Cache
    )

    $totalCachedFiles = $Cache.Count
    $filesWithFindings = ($Cache.Values | Where-Object { $_.HasFindings }).Count
    $lastUpdated = ($Cache.Values | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1).LastWriteTimeUtc

    [PSCustomObject]@{
        TotalCachedFiles = $totalCachedFiles
        FilesWithFindings = $filesWithFindings
        LastUpdated = if ($lastUpdated) { $lastUpdated.ToString("yyyy-MM-dd HH:mm:ss") } else { "N/A" }
    }
}

function Optimize-ScanCache {
    <#
    .SYNOPSIS
        Removes stale entries from the cache.
    .DESCRIPTION
        Iterates through the cache and removes entries for files that no longer exist
        in the current scan scope.
    .PARAMETER Cache
        The scan cache hashtable.
    .PARAMETER CurrentFiles
        An array of System.IO.FileInfo objects representing files found in the current scan.
    #>
    param(
        [Parameter(Mandatory)]
        [hashtable]$Cache,
        [Parameter(Mandatory)]
        [System.IO.FileInfo[]]$CurrentFiles
    )

    $currentFilePaths = $CurrentFiles.FullName | Select-Object -Unique
    $keysToRemove = @()

    foreach ($key in $Cache.Keys) {
        if (-not ($currentFilePaths -contains $key)) {
            $keysToRemove += $key
        }
    }

    foreach ($key in $keysToRemove) {
        $Cache.Remove($key)
        Write-Verbose "Removed stale entry '$key' from cache."
    }
    Write-Verbose "Cache optimized: removed $($keysToRemove.Count) stale entries."
}

Export-ModuleMember -Function @(
    'Initialize-ScanCache',
    'Save-ScanCache',
    'Test-FileChanged',
    'Update-FileCache',
    'Get-CacheStatistics',
    'Optimize-ScanCache'
) -ErrorAction SilentlyContinue
