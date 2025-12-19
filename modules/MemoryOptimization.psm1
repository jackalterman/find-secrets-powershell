# MemoryOptimization.psm1
# Memory optimization functions for PowerShell secret scanner

<#
.SYNOPSIS
    Provides functions for memory management and recommendations.
.DESCRIPTION
    This module offers tools to get current memory usage, estimate optimal
    processing parameters based on available memory, and provide warnings
    if memory consumption is expected to be high.
#>

function Get-MemoryRecommendations {
    <#
    .SYNOPSIS
        Provides memory usage recommendations for parallel processing.
    .DESCRIPTION
        Calculates estimated memory per parallel process and suggests adjustments
        to throttle limits based on available system memory.
    .PARAMETER FileCount
        Total number of files to be processed.
    .PARAMETER ThrottleLimit
        The current or proposed number of parallel threads.
    .PARAMETER AverageFileSizeKB
        The average size of files in KB.
    .RETURNS
        A PSCustomObject containing recommendations and memory usage estimates.
    #>
    param(
        [Parameter(Mandatory)]
        [int]$FileCount,
        [Parameter(Mandatory)]
        [int]$ThrottleLimit,
        [Parameter(Mandatory)]
        [double]$AverageFileSizeKB
    )

    $recommendations = [System.Collections.Generic.List[string]]::new()
    
    # Get total physical memory in MB
    $totalPhysicalMemoryMB = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1MB
    
    # Get available physical memory in MB
    $availablePhysicalMemoryMB = (Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1KB

    # Estimate memory usage per parallel process
    # This is a rough estimate. Actual usage depends on file content, regex complexity, etc.
    # Assume each process might load one file and hold some findings in memory
    $estimatedMemoryPerProcessMB = ($AverageFileSizeKB / 1024) + 5 # 5MB overhead per process

    $estimatedTotalMemoryMB = $estimatedMemoryPerProcessMB * $ThrottleLimit

    if ($estimatedTotalMemoryMB -gt ($availablePhysicalMemoryMB * 0.75)) {
        $recommendations.Add("High memory usage estimated: $($estimatedTotalMemoryMB) MB for $($ThrottleLimit) threads.")
        $recommendations.Add("Consider reducing the -ThrottleLimit parameter.")
    }
    
    [PSCustomObject]@{
        Recommendations = $recommendations.ToArray()
        EstimatedMemoryPerProcessMB = [Math]::Round($estimatedMemoryPerProcessMB, 2)
        EstimatedTotalMemoryMB = [Math]::Round($estimatedTotalMemoryMB, 2)
        TotalPhysicalMemoryMB = [Math]::Round($totalPhysicalMemoryMB, 2)
        AvailablePhysicalMemoryMB = [Math::Round($availablePhysicalMemoryMB, 2)
        CurrentMemoryMB = [Math]::Round((Get-Process -Id $PID).WorkingSet64 / 1MB, 2)
    }
}

function Get-MemoryUsage {
    <#
    .SYNOPSIS
        Gets the current and peak memory usage of the PowerShell process.
    .DESCRIPTION
        Retrieves WorkingSet (current) and PeakWorkingSet (peak) memory usage
        for the current PowerShell process.
    .RETURNS
        A PSCustomObject with WorkingSetMB and PeakWorkingSetMB properties.
    #>
    param()

    $proc = Get-Process -Id $PID
    [PSCustomObject]@{
        WorkingSetMB = [Math]::Round($proc.WorkingSet64 / 1MB, 2)
        PeakWorkingSetMB = [Math]::Round($proc.PeakWorkingSet64 / 1MB, 2)
    }
}

Export-ModuleMember -Function @(
    'Get-MemoryRecommendations',
    'Get-MemoryUsage'
) -ErrorAction SilentlyContinue
