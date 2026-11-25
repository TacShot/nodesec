<#
.SYNOPSIS
    nodesec net-installer for Windows (redirector)
.DESCRIPTION
    Redirects to the real installer in installer/install.ps1
.EXAMPLE
    iwr -useb https://raw.githubusercontent.com/TacShot/nodesec/main/install.ps1 | iex
#>

$url = "https://raw.githubusercontent.com/TacShot/nodesec/main/installer/install.ps1"
$localScript = [System.IO.Path]::GetTempPath() + "nodesec-installer.ps1"
Invoke-WebRequest -Uri $url -OutFile $localScript -UseBasicParsing

# Execute the real installer
& $localScript
