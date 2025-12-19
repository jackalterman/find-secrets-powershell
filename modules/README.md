# Performance Optimization Modules

This directory contains PowerShell modules designed to enhance the performance
of the `find_secrets.ps1` script.

## Modules:

-   **FileCache.psm1**: Implements file caching mechanisms to avoid re-scanning
    unchanged files, significantly speeding up subsequent scans.
-   **MemoryOptimization.psm1**: Provides functions for monitoring and
    optimizing memory usage during scans, helping to prevent out-of-memory
    errors and improve stability.
-   **ParallelProcessing.psm1**: Contains optimized routines for parallel
    file processing, utilizing adaptive throttling to efficiently distribute
    workload across available system resources.

These modules work together to make the `find_secrets.ps1` script more
efficient, especially when dealing with large codebases or frequent scans.
