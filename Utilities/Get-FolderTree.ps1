<#
.SYNOPSIS
    Interactive folders-only tree map with custom depth and save location.

.DESCRIPTION
    Prompts for a target path, recursion depth, and output directory/filename,
    then writes a folders-only tree view to a text file. Files are ignored;
    only directories are listed. Uses plain ASCII characters so output is
    portable across consoles and encodings.

.EXAMPLE
    .\Get-FolderTree.ps1
    (interactive - answers prompts for path, depth, output directory, filename)

.VERSION
    1.1

.AUTHOR
    ccc1236

.LASTUPDATED
    2026-04-15

.CHANGELOG
    v1.1 (2026-04-15):
      - Replaced Unicode box-drawing and emoji characters with ASCII for
        cross-encoding compatibility (fixes parser errors on Windows
        PowerShell 5.1 when file is UTF-8 without BOM)
      - Wrapped Get-ChildItem result in @() so .Count works when only one
        subfolder is returned

    v1.0:
      - Initial release

.NOTES
    Compatible with Windows PowerShell 5.1 and PowerShell 7+.
    No external modules required.
#>

Function Show-Tree {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [Parameter(Mandatory=$true)]
        [int]$MaxDepth,
        [int]$CurrentDepth = 0,
        [string]$Indent = ""
    )

    if ($CurrentDepth -ge $MaxDepth) { return }

    $folders = @(Get-ChildItem -Path $Path -Directory -ErrorAction SilentlyContinue)
    $lastIndex = $folders.Count - 1

    for ($i = 0; $i -lt $folders.Count; $i++) {
        $folder = $folders[$i]
        if ($null -eq $folder) { continue }

        if ($i -eq $lastIndex) {
            Write-Output "$Indent\- $($folder.Name)"
            Show-Tree -Path $folder.FullName -MaxDepth $MaxDepth -CurrentDepth ($CurrentDepth + 1) -Indent ("$Indent   ")
        } else {
            Write-Output "$Indent|- $($folder.Name)"
            Show-Tree -Path $folder.FullName -MaxDepth $MaxDepth -CurrentDepth ($CurrentDepth + 1) -Indent ("$Indent|  ")
        }
    }
}

# --- Prompts ---
# 1) Target path (drive or folder)
do {
    $targetPath = Read-Host 'Enter the drive or folder to scan (e.g. C:\ or D:\Shared)'
    if ([string]::IsNullOrWhiteSpace($targetPath)) { continue }
    $isValid = Test-Path -Path $targetPath -PathType Container
    if (-not $isValid) { Write-Host "[X] Path not found or not a folder. Try again." -ForegroundColor Red }
} until ($isValid)

# 2) Depth (default 3)
$maxDepthInput = Read-Host 'How many levels deep? (default 3)'
if ([string]::IsNullOrWhiteSpace($maxDepthInput)) { $maxDepth = 3 }
else {
    if ([int]::TryParse($maxDepthInput, [ref]$null)) { $maxDepth = [int]$maxDepthInput } else { $maxDepth = 3 }
}
if ($maxDepth -lt 1) { $maxDepth = 1 }

# 3) Output directory (default C:\)
$outDir = Read-Host 'Where should the output be saved? (folder path, default C:\)'
if ([string]::IsNullOrWhiteSpace($outDir)) { $outDir = 'C:\' }
if (-not (Test-Path -Path $outDir -PathType Container)) {
    try {
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    } catch {
        Write-Host "[X] Cannot create output directory at $outDir. Exiting." -ForegroundColor Red
        return
    }
}

# 4) Output filename (default auto-generated from target)
$defaultName = ("tree_{0}_depth{1}.txt" -f (($targetPath -replace '[:\\]+','_').Trim('_')), $maxDepth)
$outName = Read-Host "What should the output filename be? (default $defaultName)"
if ([string]::IsNullOrWhiteSpace($outName)) { $outName = $defaultName }
if (-not $outName.ToLower().EndsWith('.txt')) { $outName = "$outName.txt" }

$outFile = Join-Path $outDir $outName

# Confirm overwrite if file exists
if (Test-Path -Path $outFile -PathType Leaf) {
    $overwrite = Read-Host "File '$outFile' exists. Overwrite? (Y/N)"
    if ($overwrite -notmatch '^[Yy]$') {
        Write-Host "Aborted." -ForegroundColor Yellow
        return
    }
}

# --- Run and save ---
try {
    $resolved = (Resolve-Path $targetPath -ErrorAction Stop).Path
} catch {
    $resolved = $targetPath
}

# Write header line with the root path, then the tree
@($resolved) + (Show-Tree -Path $targetPath -MaxDepth $maxDepth) |
    Out-File -FilePath $outFile -Encoding utf8

Write-Host "[OK] Saved tree to: $outFile" -ForegroundColor Green
