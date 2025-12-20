#!/usr/bin/env pwsh
# Automated experimental pipeline for noisy-neighbors-detection
# Runs multiple configurations and compiles results
# Usage: powershell -ExecutionPolicy Bypass -File .\run_experiments.ps1 -NumRuns 5 -UseEdgar $true

param(
    [int]$NumRuns = 5,
    [string]$UseEdgar = "true",
    [string]$CleanUp = "false",
    [string]$SkipLoadGen = "false"
)

$UseEdgarFlag = [System.Convert]::ToBoolean($UseEdgar)
$CleanUpFlag = [System.Convert]::ToBoolean($CleanUp)
$SkipLoadGenFlag = [System.Convert]::ToBoolean($SkipLoadGen)

$RepoDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ScriptsDir = Join-Path $RepoDir "scripts"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$ResultsDir = Join-Path $ScriptsDir "results\run_${Timestamp}"

Write-Host "Noisy Neighbors Detection - Experimental Pipeline" -ForegroundColor Green
Write-Host "   Repo Dir: $RepoDir"
Write-Host "   Num Runs: $NumRuns"
Write-Host "   Skip Load Gen: $SkipLoadGenFlag"
Write-Host "   Use EDGAR: $UseEdgarFlag"
Write-Host "   Timestamp: $Timestamp"
Write-Host ""

# Step 1: Ensure Docker containers are running
Write-Host "Step 1: Starting Docker containers..." -ForegroundColor Cyan
Push-Location $RepoDir
docker compose ps | Write-Host
$WebappRunning = (docker compose ps -q webapp)
if (-not $WebappRunning) {
    Write-Host "Starting webapp and prometheus..." -ForegroundColor Yellow
    docker compose up -d
    Start-Sleep -Seconds 5
} else {
    Write-Host "Containers already running" -ForegroundColor Green
}
Pop-Location

# Step 2: Optional - Generate EDGAR profile
if ($UseEdgarFlag) {
    Write-Host ""
    Write-Host "Step 2: Generating EDGAR profile..." -ForegroundColor Cyan
    Push-Location $ScriptsDir

    if (-not (Test-Path "edgar_profile.json")) {
        Write-Host "Running edgar_calibrator.py..." -ForegroundColor Yellow
        & python edgar_calibrator.py --input-dir ./edgar_data --output edgar_profile.json --sample-ratio 0.05 --max-files 2
        Write-Host "EDGAR profile created" -ForegroundColor Green
    } else {
        Write-Host "EDGAR profile already exists" -ForegroundColor Green
    }
    Pop-Location
} else {
    Write-Host ""
    Write-Host "Skipping EDGAR profile generation" -ForegroundColor Yellow
}

# Step 3: Clean up old results if requested
if ($CleanUpFlag) {
    Write-Host ""
    Write-Host "Cleaning up old data..." -ForegroundColor Cyan
    Push-Location $ScriptsDir
    Remove-Item -Force -ErrorAction SilentlyContinue telemetry.csv, replay_plan.json, telemetry_labeled.csv
    Remove-Item -Force -ErrorAction SilentlyContinue telemetry_labeled_*.csv
    Pop-Location
    Write-Host "Cleaned" -ForegroundColor Green
}

# Step 4: Run experiments
Write-Host ""
Write-Host "Step 3: Running $NumRuns experimental runs..." -ForegroundColor Cyan
Write-Host "   Results will be saved to: $ResultsDir" -ForegroundColor Cyan

# Create output directories
New-Item -ItemType Directory -Force -Path $ResultsDir | Out-Null
$TelemetryDir = Join-Path $ResultsDir "telemetry"
$LabelsDir = Join-Path $ResultsDir "labeled"
New-Item -ItemType Directory -Force -Path $TelemetryDir | Out-Null
New-Item -ItemType Directory -Force -Path $LabelsDir | Out-Null

Push-Location $ScriptsDir

# If SkipLoadGen, copy telemetry from most recent previous run
if ($SkipLoadGenFlag) {
    $ResultsBaseDir = Join-Path $ScriptsDir "results"
    $PreviousRuns = Get-ChildItem -Path $ResultsBaseDir -Directory -Filter "run_*" | 
                    Where-Object { $_.Name -ne "run_${Timestamp}" } |
                    Sort-Object Name -Descending
    
    if ($PreviousRuns.Count -gt 0) {
        $MostRecentRun = $PreviousRuns[0]
        $SourceTelemetryDir = Join-Path $MostRecentRun.FullName "telemetry"
        
        if (Test-Path $SourceTelemetryDir) {
            Write-Host "  Copying telemetry from previous run: $($MostRecentRun.Name)" -ForegroundColor Cyan
            Copy-Item -Path "$SourceTelemetryDir\*.csv" -Destination $TelemetryDir -Force
            $CopiedCount = (Get-ChildItem -Path $TelemetryDir -Filter "*.csv").Count
            Write-Host "  Copied $CopiedCount telemetry file(s)" -ForegroundColor Green
        } else {
            Write-Host "  Warning: No telemetry found in previous run" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  Warning: No previous runs found for SkipLoadGen mode" -ForegroundColor Yellow
    }
}

$Configs = @(
    @{ attacker = "tenant_99"; delay = 0.001; warmup = 60; cooldown = 60; window = 60; seed = 42; suffix = "aggressive" },
    @{ attacker = "tenant_05"; delay = 0.005; warmup = 60; cooldown = 60; window = 60; seed = 123; suffix = "medium" },
    @{ attacker = "tenant_08"; delay = 0.01;  warmup = 60; cooldown = 60; window = 30; seed = 456; suffix = "light" },
    @{ attacker = "tenant_02"; delay = 0.005; warmup = 60; cooldown = 60; window = 120; seed = 789; suffix = "wide_window" },
    @{ attacker = "tenant_99"; delay = 0.002; warmup = 60; cooldown = 60; window = 60; seed = 999; suffix = "short_warmup" }
) | Select-Object -First $NumRuns

$RunNumber = 0
foreach ($Config in $Configs) {
    $RunNumber++
    Write-Host ""
    Write-Host "Run $RunNumber/${NumRuns}: attacker=$($Config.attacker), delay=$($Config.delay)s, warmup=$($Config.warmup)s, window=$($Config.window)s" -ForegroundColor Yellow
    $TelemetryFile = Join-Path $TelemetryDir "telemetry_run${RunNumber}.csv"
    $RunOutputDir = Join-Path $LabelsDir "run${RunNumber}"
    New-Item -ItemType Directory -Force -Path $RunOutputDir | Out-Null
    
    if (-not $SkipLoadGenFlag) {
        # Load generator
        Write-Host "  Generating load..." -ForegroundColor Gray
        $EdgarArg = if ($UseEdgarFlag) { "--edgar-profile edgar_profile.json" } else { "" }
        Invoke-Expression "python load_generator.py --attacker $($Config.attacker) --attack-delay $($Config.delay) --warmup $($Config.warmup) --cooldown $($Config.cooldown) --seed $($Config.seed) $EdgarArg"
        
        # Copy telemetry from container
        Write-Host "  Copying telemetry from container..." -ForegroundColor Gray
        $cid = docker compose ps -q webapp
        if ($cid) {
            $src = "${cid}:/app/telemetry.csv"
            docker cp $src "$TelemetryFile"
        } else {
            Write-Host "  Container not accessible; skipping" -ForegroundColor Yellow
            continue
        }
    } else {
        Write-Host "  Skipping load generation, using existing ${TelemetryFile}..." -ForegroundColor Gray
        if (-not (Test-Path $TelemetryFile)) {
            Write-Host "  ${TelemetryFile} not found; skipping this run" -ForegroundColor Yellow
            continue
        }
    }
    
    # Generate attacker-specific replay plan for ground truth, anchored to this run's telemetry
    Write-Host "  Generating replay_plan.json for $($Config.attacker)..." -ForegroundColor Gray
    & python generate_replay_plan.py --attacker $($Config.attacker) --warmup $($Config.warmup) --cooldown $($Config.cooldown) --attack-duration 120 --derive-from "$TelemetryFile" --output replay_plan.json | Out-Null
    
    # Analyze with optimized parameters
    Write-Host "  Running analysis..." -ForegroundColor Gray
    $AnalysisParams = "--window $($Config.window) --overlap 0.5 --contamination 0.15 --estimators 400 --z-threshold 1.8 --rel-threshold 0.18 --hysteresis 2 --attrib-topk 3"
    Invoke-Expression "python analysis.py $AnalysisParams --input `"${TelemetryFile}`" --output-dir `"${RunOutputDir}`"" | Tee-Object -Variable "AnalysisOutput"
    
    # Copy labeled output to main results folder with descriptive name
    $LabeledSource = Join-Path $RunOutputDir "telemetry_labeled.csv"
    if (Test-Path $LabeledSource) {
        $LabeledDest = Join-Path $LabelsDir "telemetry_labeled_$($Config.attacker)_$($Config.window)s_seed$($Config.seed).csv"
        Copy-Item -Force $LabeledSource $LabeledDest
        Write-Host "  Results saved to $RunOutputDir" -ForegroundColor Green
    }
    
    Start-Sleep -Seconds 2
}

# Step 5: Compile results
Write-Host ""
Write-Host "Step 4: Compiling results..." -ForegroundColor Cyan
$SummaryFile = Join-Path $ResultsDir "results_summary.csv"
# Compute relative paths manually (GetRelativePath not available in PS 5.1)
$PatternRelative = "results\run_${Timestamp}\labeled\telemetry_labeled_*.csv"
$OutputRelative = "results\run_${Timestamp}\results_summary.csv"
& python compile_results.py --pattern "$PatternRelative" --output "$OutputRelative"

if (Test-Path $SummaryFile) {
    Write-Host ""
    Write-Host "Summary table:" -ForegroundColor Green
    Get-Content $SummaryFile
}

Pop-Location

Write-Host ""
Write-Host "Experimental pipeline complete!" -ForegroundColor Green
Write-Host "   Results directory: $ResultsDir" -ForegroundColor Gray
Write-Host "   Summary: results_summary.csv" -ForegroundColor Gray
Write-Host "   Telemetry CSVs: telemetry\" -ForegroundColor Gray
Write-Host "   Labeled data: labeled\" -ForegroundColor Gray
Write-Host "   Visualizations: labeled\run*\" -ForegroundColor Gray
