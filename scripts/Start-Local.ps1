[CmdletBinding()]
param(
    [string]$EnvironmentFile = (Join-Path $PSScriptRoot '..\.env'),
    [switch]$SkipDatabaseCheck
)

$ErrorActionPreference = 'Stop'

function Import-DotEnv {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Environment file not found: $Path. Copy .env.example to .env and replace its placeholders."
    }

    foreach ($line in Get-Content -LiteralPath $Path) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith('#')) { continue }

        $parts = $trimmed -split '=', 2
        if ($parts.Count -ne 2 -or [string]::IsNullOrWhiteSpace($parts[0])) {
            throw "Invalid line in ${Path}: $line"
        }

        $name = $parts[0].Trim()
        $value = $parts[1].Trim()
        if (($value.StartsWith('"') -and $value.EndsWith('"')) -or
            ($value.StartsWith("'") -and $value.EndsWith("'"))) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        [Environment]::SetEnvironmentVariable($name, $value, 'Process')
    }
}

function Require-Value {
    param([Parameter(Mandatory)][string]$Name)

    $value = [Environment]::GetEnvironmentVariable($Name, 'Process')
    if ([string]::IsNullOrWhiteSpace($value) -or $value.StartsWith('replace-with-')) {
        throw "$Name is missing or still contains its placeholder value in $EnvironmentFile."
    }
    return $value
}

$dotnet = Get-Command dotnet -ErrorAction SilentlyContinue
if (-not $dotnet) {
    throw 'The .NET 10 SDK is required. Install it, then run this command again.'
}

$sdkVersions = & $dotnet.Source --list-sdks
if (-not ($sdkVersions | Where-Object { $_ -match '^10\.' })) {
    throw 'The project targets .NET 10, but no .NET 10 SDK was found.'
}

Import-DotEnv -Path $EnvironmentFile

$database = Require-Value -Name 'POSTGRES_DB'
$databaseUser = Require-Value -Name 'POSTGRES_USER'
$databasePassword = Require-Value -Name 'POSTGRES_PASSWORD'
$adminEmail = Require-Value -Name 'BOOTSTRAP_ADMIN_EMAIL'
$adminPassword = Require-Value -Name 'BOOTSTRAP_ADMIN_PASSWORD'

if ($adminPassword.Length -lt 8) {
    throw 'BOOTSTRAP_ADMIN_PASSWORD must contain at least 8 characters.'
}

$env:ConnectionStrings__KudosWall = "Host=localhost;Port=5432;Database=$database;Username=$databaseUser;Password=$databasePassword"
$env:BootstrapAdmin__Email = $adminEmail
$env:BootstrapAdmin__Password = $adminPassword
$env:Cors__AllowedOrigins__0 = 'https://www.kudos-evotix.com'
$env:Cors__AllowedOrigins__1 = 'http://localhost:3000'
$env:ASPNETCORE_ENVIRONMENT = 'Development'

if (-not $SkipDatabaseCheck) {
    $tcpClient = [System.Net.Sockets.TcpClient]::new()
    try {
        $connect = $tcpClient.ConnectAsync('localhost', 5432)
        if (-not $connect.Wait([TimeSpan]::FromSeconds(3)) -or -not $tcpClient.Connected) {
            throw 'PostgreSQL is not reachable on localhost:5432.'
        }
    }
    finally {
        $tcpClient.Dispose()
    }
}

$project = Join-Path $PSScriptRoot '..\KudosWall.Api\KudosWall.Api.csproj'
Write-Host 'Starting Kudos Wall API at http://localhost:5080'
& $dotnet.Source run --project $project --launch-profile http
exit $LASTEXITCODE
