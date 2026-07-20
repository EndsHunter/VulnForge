# Start bethington/ghidra-mcp headless HTTP server (default :8089).
# Paths default relative to the VulnForge project root (parent of scripts/).
#
# Layout expected:
#   <project>/ghidra/              Ghidra distribution
#   <project>/ghidra-mcp/build/libs/GhidraMCP*.jar
#
# Usage (from anywhere):
#   powershell -ExecutionPolicy Bypass -File scripts\start_ghidra_mcp_headless.ps1
#   powershell -File scripts\start_ghidra_mcp_headless.ps1 -File C:\path\app.exe

param(
    [string]$GhidraHome = "",
    [string]$McpJar = "",
    [string]$Bind = "127.0.0.1",
    [int]$Port = 8089,
    [string]$File = "",
    [string]$Project = "",
    [string]$JavaHome = ""
)

$ErrorActionPreference = "Stop"

# Project root = parent of scripts/
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

if (-not $GhidraHome) {
    $GhidraHome = Join-Path $ProjectRoot "ghidra"
}
if (-not [System.IO.Path]::IsPathRooted($GhidraHome)) {
    $GhidraHome = Join-Path $ProjectRoot $GhidraHome
}
$GhidraHome = [System.IO.Path]::GetFullPath($GhidraHome)

if (-not $McpJar) {
    $candidates = @(
        (Join-Path $ProjectRoot "ghidra-mcp\build\libs\GhidraMCP-5.15.0.jar"),
        (Join-Path $ProjectRoot "ghidra-mcp\build\libs\GhidraMCP.jar")
    )
    $libsDir = Join-Path $ProjectRoot "ghidra-mcp\build\libs"
    if (Test-Path $libsDir) {
        Get-ChildItem $libsDir -Filter "GhidraMCP*.jar" -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending |
            ForEach-Object { $candidates = @($_.FullName) + $candidates }
    }
    if ($env:APPDATA) {
        $extRoot = Join-Path $env:APPDATA "ghidra"
        if (Test-Path $extRoot) {
            Get-ChildItem $extRoot -Recurse -Filter "GhidraMCP*.jar" -ErrorAction SilentlyContinue |
                ForEach-Object { $candidates += $_.FullName }
        }
    }
    foreach ($c in $candidates) {
        if ($c -and (Test-Path $c) -and $c.ToLower().EndsWith(".jar")) {
            $McpJar = [System.IO.Path]::GetFullPath($c)
            break
        }
    }
} elseif (-not [System.IO.Path]::IsPathRooted($McpJar)) {
    $McpJar = [System.IO.Path]::GetFullPath((Join-Path $ProjectRoot $McpJar))
}

if (-not (Test-Path $GhidraHome)) {
    throw "Ghidra home not found: $GhidraHome (expected project-relative 'ghidra/' distribution)"
}
if (-not $McpJar -or -not (Test-Path $McpJar)) {
    throw "GhidraMCP jar not found under ghidra-mcp/build/libs. Build ghidra-mcp first."
}

if (-not $JavaHome) {
    $candidatesJh = @(
        $env:JAVA_HOME,
        "C:\Program Files\Eclipse Adoptium\jdk-25.0.3.9-hotspot",
        "C:\Program Files\Eclipse Adoptium\jdk-21.0.7.6-hotspot",
        "C:\Program Files\Java\jdk-25",
        "C:\Program Files\Java\jdk-21"
    )
    foreach ($jh in $candidatesJh) {
        if ($jh -and (Test-Path (Join-Path $jh "bin\java.exe"))) {
            $JavaHome = $jh
            break
        }
    }
}

$java = if ($JavaHome -and (Test-Path (Join-Path $JavaHome "bin\java.exe"))) {
    Join-Path $JavaHome "bin\java.exe"
} else {
    "java"
}

# Build classpath: MCP jar + all Ghidra module jars
$cp = New-Object System.Collections.Generic.List[string]
$cp.Add($McpJar)
foreach ($sub in @("Framework", "Features", "Processors", "Configurations", "Debug")) {
    $root = Join-Path $GhidraHome "Ghidra\$sub"
    if (Test-Path $root) {
        Get-ChildItem -Path $root -Recurse -Filter "*.jar" -ErrorAction SilentlyContinue |
            ForEach-Object { $cp.Add($_.FullName) }
    }
}
$ls = Join-Path $GhidraHome "support\LaunchSupport.jar"
if (Test-Path $ls) { $cp.Add($ls) }

$classpath = ($cp | Select-Object -Unique) -join ";"

$argsList = @(
    "-Xmx4G",
    "-Dghidra.home=$GhidraHome",
    "-Dapplication.name=GhidraMCP",
    "-classpath", $classpath,
    "com.xebyte.headless.GhidraMCPHeadlessServer",
    "--port", "$Port",
    "--bind", $Bind
)
if ($File) {
    $argsList += @("--file", $File)
}
if ($Project) {
    $argsList += @("--project", $Project)
}

Write-Host "Starting GhidraMCP headless on http://${Bind}:${Port}"
Write-Host "  Project: $ProjectRoot"
Write-Host "  Ghidra:  $GhidraHome"
Write-Host "  JAR:     $McpJar"
Write-Host "  Java:    $java"
& $java @argsList
