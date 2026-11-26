<#
.SYNOPSIS
    nodesec net-installer for Windows
.DESCRIPTION
    Cross-platform net-installer for nodesec System and Network Security Platform.
    Downloads and installs the latest nodesec release with all dependencies.
    Falls back to building from source when no GitHub Release is available.
    Auto-restarts PowerShell after installing Rust toolchain so PATH is recognized.
.EXAMPLE
    # Install latest version
    iwr -useb https://raw.githubusercontent.com/TacShot/nodesec/main/installer/install.ps1 | iex

    # Install specific version from source
    iwr -useb https://raw.githubusercontent.com/TacShot/nodesec/main/installer/install.ps1 | iex -- --from-source --version 0.1.0

    # Install system-wide (requires admin)
    iwr -useb https://raw.githubusercontent.com/TacShot/nodesec/main/installer/install.ps1 | iex -- --target system

    # Uninstall
    iwr -useb https://raw.githubusercontent.com/TacShot/nodesec/main/installer/install.ps1 | iex -- --uninstall
#>

param(
    [switch]$FromSource,
    [string]$Version,
    [string]$Prefix,
    [switch]$SkipDeps,
    [switch]$Force,
    [switch]$DryRun,
    [switch]$Verbose,
    [ValidateSet('user', 'system')]
    [string]$Target = 'user',
    [switch]$Uninstall,
    [switch]$Help,
    [switch]$Resume
)

$REPO = "TacShot/nodesec"
$BINARY = "nodesec.exe"
$INSTALLER_VERSION = "0.1.0"
$FALLBACK_VERSION = "0.1.0"
$DEFAULT_INSTALL_DIR = 'C:\nodesec'

function Write-Info { param($msg) Write-Host "[INFO] $msg" -ForegroundColor Cyan }
function Write-Success { param($msg) Write-Host "[SUCCESS] $msg" -ForegroundColor Green }
function Write-Warn { param($msg) Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Write-Error { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red }

function Show-Help {
    @"
nodesec-installer v$using:INSTALLER_VERSION
Cross-platform net-installer for nodesec System and Network Security Platform

Usage: install.ps1 [OPTIONS]

Options:
    --from-source       Build from source instead of downloading pre-built binary
    --version VERSION   Install specific version (default: latest)
    --prefix PATH       Install to custom directory (default: C:\nodesec)
    --skip-deps         Skip system dependency installation
    --force             Force reinstall even if already installed
    --dry-run           Show what would be done without installing
    --verbose           Verbose output
    --target TARGET     Installation target: user (default) or system
    --uninstall         Uninstall nodesec
    --resume            Resume after PowerShell restart (internal)
    --help              Show this help

Examples:
    # Install latest version for current user
    iwr -useb https://raw.githubusercontent.com/TacShot/nodesec/main/installer/install.ps1 | iex

    # Install specific version from source
    iwr -useb https://raw.githubusercontent.com/TacShot/nodesec/main/installer/install.ps1 | iex -- --from-source --version 0.1.0

    # Install system-wide (requires admin)
    iwr -useb https://raw.githubusercontent.com/TacShot/nodesec/main/installer/install.ps1 | iex -- --target system

    # Uninstall
    iwr -useb https://raw.githubusercontent.com/TacShot/nodesec/main/installer/install.ps1 | iex -- --uninstall
"@
}

if ($Help) { Show-Help; exit 0 }

# If resuming after PowerShell restart, skip the rustup restart step
if ($Resume) {
    $env:RESUMING = '1'
}

if ($Uninstall) {
    $installDir = if ($Prefix) { $Prefix } elseif ($Target -eq 'system') { 'C:\Program Files\nodesec' } else { $DEFAULT_INSTALL_DIR }
    $binary = Join-Path $installDir $BINARY_NAME
    if (Test-Path $binary) {
        Remove-Item $binary -Force
        Write-Success ("Removed binary: " + $binary)
    }
    $shortcutPath = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\NODESEC System and Network Security.lnk'
    if (Test-Path $shortcutPath) {
        Remove-Item $shortcutPath -Force
        Write-Success 'Removed Start Menu shortcut'
    }
    Write-Success 'Uninstall complete.'
    exit 0
}

# Detect architecture
$ARCH = [Environment]::GetEnvironmentVariable("PROCESSOR_ARCHITECTURE")
if ($ARCH -eq "AMD64") { $ASSET_PATTERN = "nodesec-x86_64-pc-windows-msvc" }
elseif ($ARCH -eq "ARM64") { $ASSET_PATTERN = "nodesec-aarch64-pc-windows-msvc" }
else { Write-Error "Unsupported architecture: $ARCH"; exit 1 }

$BINARY_NAME = "nodesec.exe"

function Get-InstallDir {
    if ($Prefix) { return $Prefix }
    if ($Target -eq 'system') { return 'C:\Program Files\nodesec' }
    return $DEFAULT_INSTALL_DIR
}

function Is-Installed {
    $installDir = Get-InstallDir
    return Test-Path (Join-Path $installDir $BINARY_NAME)
}

function Get-LatestVersion {
    Write-Info 'Fetching latest version...'
    try {
        $url = 'https://api.github.com/repos/' + $REPO + '/releases/latest'
        $response = Invoke-RestMethod -Uri $url -Headers @{ "Accept" = "application/vnd.github.v3+json" } -ErrorAction Stop
        $version = $response.tag_name.TrimStart('v')
        Write-Info ('Found release: ' + $version)
        return $version
    }
    catch {
        Write-Warn 'No GitHub Release found. Will fall back to building from source.'
        return $FALLBACK_VERSION
    }
}

function Install-Dependencies {
    Write-Info 'Checking and installing system dependencies...'

    # Check for winget (Windows 10 1709+)
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Info 'winget found. Installing required packages via winget...'

        # Install Git
        $gitInstalled = Get-Command git -ErrorAction SilentlyContinue
        if (-not $gitInstalled) {
            Write-Info 'Installing Git via winget...'
            winget install --id Git.Git -e --accept-package-agreements --accept-source-agreements 2>&1 | Out-Null
        }

        # Install Rust
        $rustInstalled = Get-Command cargo -ErrorAction SilentlyContinue
        if (-not $rustInstalled) {
            Write-Info 'Installing Rust via winget...'
            winget install --id Rustlang.Rustup -e --accept-package-agreements --accept-source-agreements 2>&1 | Out-Null
        }

        # Install Visual Studio Build Tools (MSVC linker)
        $vsBuildToolsInstalled = Test-Path 'C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
        if (-not $vsBuildToolsInstalled) {
            Write-Info 'Installing Visual Studio Build Tools via winget...'
            winget install --id Microsoft.VisualStudio.2022.BuildTools -e --accept-package-agreements --accept-source-agreements --add 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64' 2>&1 | Out-Null

            # Wait for VS Build Tools installation to complete (race condition handling)
            Write-Info 'Waiting for Visual Studio Build Tools installation to complete...'
            $maxWait = 300  # 5 minutes max
            $elapsed = 0
            while ($elapsed -lt $maxWait) {
                if (Test-Path 'C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat') {
                    break
                }
                Start-Sleep -Seconds 10
                $elapsed += 10
            }

            if (-not (Test-Path 'C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat')) {
                Write-Warn 'Visual Studio Build Tools installation may still be in progress.'
                Write-Warn 'Please complete the Visual Studio Installer UI if it is still open.'
                Write-Warn 'Then re-run this script.'
                exit 1
            }
        }

        Write-Success 'Dependencies check complete via winget.'
    }
    elseif (Get-Command choco -ErrorAction SilentlyContinue) {
        Write-Info 'Chocolatey found. Installing required packages via choco...'

        # Install Git
        $gitInstalled = Get-Command git -ErrorAction SilentlyContinue
        if (-not $gitInstalled) {
            Write-Info 'Installing Git via choco...'
            choco install git -y 2>&1 | Out-Null
        }

        # Install Rust
        $rustInstalled = Get-Command cargo -ErrorAction SilentlyContinue
        if (-not $rustInstalled) {
            Write-Info 'Installing Rust via choco...'
            choco install rustup -y 2>&1 | Out-Null
        }

        # Install Visual Studio Build Tools (MSVC linker for cargo)
        $vsBuildToolsPath = 'C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
        $vsBuildToolsInstalled = Test-Path $vsBuildToolsPath
        if (-not $vsBuildToolsInstalled) {
            Write-Info 'Installing Visual Studio Build Tools via choco...'
            choco install visualstudio2022buildtools -y --package-parameters '--add Microsoft.VisualStudio.Component.VC.Tools.x86.x64' 2>&1 | Out-Null

            # Wait for VS Build Tools installation to complete (race condition handling)
            Write-Info 'Waiting for Visual Studio Build Tools installation to complete...'
            $maxWait = 300  # 5 minutes max
            $elapsed = 0
            while ($elapsed -lt $maxWait) {
                if (Test-Path $vsBuildToolsPath) {
                    break
                }
                Start-Sleep -Seconds 10
                $elapsed += 10
            }

            if (-not (Test-Path $vsBuildToolsPath)) {
                Write-Warn 'Visual Studio Build Tools installation may still be in progress.'
                Write-Warn 'Please complete the Visual Studio Installer UI if it is still open.'
                Write-Warn 'Then re-run this script.'
                exit 1
            }
        }

        Write-Success 'Dependencies check complete via chocolatey.'
    }
    elseif (Get-Command scoop -ErrorAction SilentlyContinue) {
        Write-Info 'Scoop found. Installing required packages via scoop...'

        # Install Git
        $gitInstalled = Get-Command git -ErrorAction SilentlyContinue
        if (-not $gitInstalled) {
            Write-Info 'Installing Git via scoop...'
            scoop install git 2>&1 | Out-Null
        }

        # Install Rust
        $rustInstalled = Get-Command cargo -ErrorAction SilentlyContinue
        if (-not $rustInstalled) {
            Write-Info 'Installing Rust via scoop...'
            scoop install rust 2>&1 | Out-Null
        }

        Write-Warn 'Scoop does not provide Visual Studio Build Tools. Please install manually from https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022'
        Write-Success 'Dependencies check complete via scoop.'
    }
    else {
        Write-Warn 'No package manager found (winget/choco/scoop).'
        Write-Info 'Installing chocolatey package manager...'
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
            Write-Error 'Chocolatey installation failed. Please install manually: https://chocolatey.org/install'
            exit 1
        }
        Write-Info 'chocolatey installed. Installing required packages via choco...'
        choco install git -y 2>&1 | Out-Null
        choco install rustup -y 2>&1 | Out-Null

        # Install Visual Studio Build Tools via choco
        $vsBuildToolsPath = 'C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
        $vsBuildToolsInstalled = Test-Path $vsBuildToolsPath
        if (-not $vsBuildToolsInstalled) {
            Write-Info 'Installing Visual Studio Build Tools via choco...'
            choco install visualstudio2022buildtools -y --package-parameters '--add Microsoft.VisualStudio.Component.VC.Tools.x86.x64' 2>&1 | Out-Null

            # Wait for VS Build Tools installation to complete (race condition handling)
            Write-Info 'Waiting for Visual Studio Build Tools installation to complete...'
            $maxWait = 300  # 5 minutes max
            $elapsed = 0
            while ($elapsed -lt $maxWait) {
                if (Test-Path $vsBuildToolsPath) {
                    break
                }
                Start-Sleep -Seconds 10
                $elapsed += 10
            }

            if (-not (Test-Path $vsBuildToolsPath)) {
                Write-Warn 'Visual Studio Build Tools installation may still be in progress.'
                Write-Warn 'Please complete the Visual Studio Installer UI if it is still open.'
                Write-Warn 'Then re-run this script.'
                exit 1
            }
        }

        Write-Success 'Dependencies check complete via chocolatey.'
    }
}

function Install-Binary {
    param($version)
    $assetName = $ASSET_PATTERN + '-' + $version + '.zip'
    $downloadUrl = 'https://github.com/' + $REPO + '/releases/download/v' + $version + '/' + $assetName

    Write-Info ('Downloading ' + $BINARY + ' ' + $version + ' from ' + $downloadUrl)

    try {
        Invoke-WebRequest -Uri $downloadUrl -OutFile ([System.IO.Path]::GetTempPath() + 'nodesec-install.zip') -UseBasicParsing -ErrorAction Stop
    }
    catch {
        Write-Warn ('Binary download failed (' + $_.Exception.Message + '). Falling back to source build.')
        Install-FromSource -version $version
        return
    }

    $tempDir = [System.IO.Path]::GetTempPath() + 'nodesec-install-' + [Guid]::NewGuid()
    New-Item -ItemType Directory -Path $tempDir | Out-Null
    $archivePath = Join-Path $tempDir 'nodesec-install.zip'

    Expand-Archive -Path $archivePath -DestinationPath $tempDir -Force

    $binaryPath = Get-ChildItem -Path $tempDir -Filter $BINARY_NAME -Recurse | Select-Object -First 1
    if (-not $binaryPath) {
        Write-Warn 'Binary not found in archive. Falling back to source build.'
        Install-FromSource -version $version
        return
    }

    $installDir = Get-InstallDir
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null

    Copy-Item $binaryPath.FullName (Join-Path $installDir $BINARY_NAME) -Force

    Write-Success ('Installed to ' + $installDir + '\' + $BINARY_NAME)
}

function Install-FromSource {
    param($version)
    Write-Info ('Building nodesec ' + $version + ' from source...')

    # Check if git is installed
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        Write-Error 'Git is not installed. Please install Git from https://git-scm.com/download/win and try again.'
        exit 1
    }

    # Check if cargo is installed
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        Write-Info 'Rust toolchain not found. Installing via rustup...'

        # Save resume state so we know to continue after restart
        $resumeFile = [System.IO.Path]::GetTempPath() + 'nodesec-resume.txt'
        Set-Content -Path $resumeFile -Value '1'

        # Launch new PowerShell window with resume flag
        $scriptPath = $PSCommandPath
        if (-not $scriptPath) {
            $scriptPath = $PSScriptRoot
        }
        if (-not $scriptPath -or $scriptPath -eq '') {
            $scriptPath = 'https://raw.githubusercontent.com/TacShot/nodesec/main/installer/install.ps1'
            $downloadUrl = $scriptPath
            $localScript = [System.IO.Path]::GetTempPath() + 'nodesec-installer.ps1'
            Invoke-WebRequest -Uri $downloadUrl -OutFile $localScript -UseBasicParsing
            $scriptPath = $localScript
        }

        $args = '--resume --version ' + $version
        if ($FromSource) { $args += ' --from-source' }
        if ($SkipDeps) { $args += ' --skip-deps' }
        if ($Force) { $args += ' --force' }
        if ($Target -eq 'system') { $args += ' --target system' }
        if ($Prefix) { $args += ' --prefix ' + $Prefix }

        Write-Info 'Launching new PowerShell window to continue after Rust install...'
        Start-Process powershell.exe -ArgumentList '-NoExit -ExecutionPolicy Bypass -File "' + $scriptPath + '" ' + $args

        Write-Warn 'New PowerShell window launched. Please complete the installation there.'
        Write-Warn 'This window will close. Continue in the new window.'
        exit 0
    }

    $tempDir = [System.IO.Path]::GetTempPath() + 'nodesec-build-' + [Guid]::NewGuid()
    New-Item -ItemType Directory -Path $tempDir | Out-Null

    # Clone the repository (default branch)
    Write-Info 'Cloning repository...'
    $repoUrl = 'https://github.com/' + $REPO + '.git'
    git clone --depth 1 $repoUrl $tempDir
    if ($LASTEXITCODE -ne 0) {
        Write-Error 'Git clone failed. Installation aborted.'
        exit 1
    }

    Set-Location $tempDir

    # Verify Cargo.toml exists before building
    if (-not (Test-Path (Join-Path $tempDir 'Cargo.toml'))) {
        Write-Error 'Cargo.toml not found in cloned repository. Installation aborted.'
        exit 1
    }

    Write-Info 'Building with cargo...'
    cargo build --release --workspace
    if ($LASTEXITCODE -ne 0) {
        Write-Error 'Cargo build failed. Installation aborted.'
        Write-Error 'On Windows, ensure Visual Studio Build Tools with C++ workload is installed.'
        Write-Error 'Download: https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022'
        exit 1
    }

    $installDir = Get-InstallDir
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null

    $anyBinaryCopied = $false
    foreach ($binary in @('nodesec.exe', 'nodesec-cli.exe', 'nodesec-tui.exe', 'nodesec-gui.exe', 'nodesec-installer.exe')) {
        $src = 'target\release\' + $binary
        if (Test-Path $src) {
            Copy-Item $src (Join-Path $installDir $binary) -Force
            $anyBinaryCopied = $true
        }
    }

    if (-not $anyBinaryCopied) {
        Write-Error 'No binaries were produced by the build. Installation aborted.'
        exit 1
    }

    Write-Success 'Built and installed from source'
}

function Create-Shortcuts {
    $installDir = Get-InstallDir
    $binary = Join-Path $installDir $BINARY_NAME

    $shortcutPath = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\NODESEC System and Network Security.lnk'
    $WshShell = New-Object -ComObject WScript.Shell
    $shortcut = $WshShell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = $binary
    $shortcut.Description = 'NODESEC System and Network Security Platform'
    $shortcut.Save()

    Write-Success 'Created Start Menu shortcut'
}

function Add-ToPath {
    $installDir = Get-InstallDir
    $currentPath = [Environment]::GetEnvironmentVariable("PATH", "User")

    if ($currentPath -notlike '*' + $installDir + '*') {
        $newPath = $currentPath + ';' + $installDir
        [Environment]::SetEnvironmentVariable("PATH", $newPath, "User")
        Write-Success ('Added ' + $installDir + ' to user PATH')
        Write-Warn 'Please restart your terminal for PATH changes to take effect'
    }
}

function Uninstall {
    Write-Info 'Uninstalling nodesec...'

    $installDir = if ($Prefix) { $Prefix } elseif ($Target -eq 'system') { 'C:\Program Files\nodesec' } else { $DEFAULT_INSTALL_DIR }
    $binary = Join-Path $installDir $BINARY_NAME

    if (Test-Path $binary) {
        Remove-Item $binary -Force
        Write-Success ('Removed binary: ' + $binary)
    }

    $shortcutPath = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\NODESEC System and Network Security.lnk'
    if (Test-Path $shortcutPath) {
        Remove-Item $shortcutPath -Force
        Write-Success 'Removed Start Menu shortcut'
    }

    Write-Success 'Uninstall complete.'
    exit 0
}

function Print-PostInstallInfo {
    $installDir = Get-InstallDir
    Write-Host
    Write-Success 'Installation complete!'
    Write-Host ('Binary installed to: ' + $installDir)
    Write-Host "Run 'nodesec --help' to get started"
    Write-Host
    Write-Host 'Note: Please restart your terminal for PATH changes to take effect.'
}

# Main execution
Write-Host ('nodesec-installer v' + $INSTALLER_VERSION) -ForegroundColor Cyan
Write-Host 'Cross-platform net-installer for nodesec System and Network Security Platform'
Write-Host

if ($Uninstall) { Uninstall; exit 0 }

if (-not $Version) {
    $Version = Get-LatestVersion
    Write-Info ('Latest version: ' + $Version)
}

if ($DryRun) {
    Write-Info ('[DRY RUN] Would install ' + $BINARY + ' ' + $Version + ' for ' + $ASSET_PATTERN)
    exit 0
}

if (-not $Force -and (Is-Installed)) {
    Write-Warn ($BINARY_NAME + ' is already installed. Use --force to reinstall.')
    exit 0
}

if (-not $SkipDeps) {
    Install-Dependencies
}

if ($FromSource) {
    Install-FromSource -version $Version
} else {
    Install-Binary -version $Version
}

Create-Shortcuts
Add-ToPath

Write-Host
Write-Success 'Installation complete!'
Write-Host ('Binary installed to: ' + (Get-InstallDir))
Write-Host "Run 'nodesec --help' to get started"
Write-Host
Write-Host 'Note: Please restart your terminal for PATH changes to take effect.'