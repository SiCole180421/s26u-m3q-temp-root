param(
  [string]$NdkRoot = $env:ANDROID_NDK_HOME
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$exploitRoot = Join-Path $repoRoot 'exploit'

if ([string]::IsNullOrWhiteSpace($NdkRoot)) {
  $ndkHome = Join-Path $env:LOCALAPPDATA 'Android\Sdk\ndk'
  $NdkRoot = (Get-ChildItem -LiteralPath $ndkHome -Directory |
      Sort-Object Name -Descending | Select-Object -First 1).FullName
}
$compiler = Join-Path $NdkRoot 'toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android35-clang.cmd'
if (-not (Test-Path -LiteralPath $compiler)) {
  throw "Android NDK compiler not found: $compiler"
}

$outputDir = Join-Path $exploitRoot 'build\m3q-BP4A.251205.006\bin'
New-Item -ItemType Directory -Force -Path $outputDir | Out-Null

$helperArgs = @(
  '-O2', '-g0', '-Wall', '-Wextra', '-Werror', '-Isrc', '-fPIE', '-pie',
  'src\su_daemon.c', '-ldl', '-o',
  'build\m3q-BP4A.251205.006\bin\su_daemon_aarch64_pie.app'
)
$oracleArgs = @(
  '-O2', '-g0', '-Wall', '-Wextra', '-Werror',
  '-Wno-unused-parameter', '-Wno-sign-compare', '-Wno-unused-function',
  '-DAPP_PAYLOAD=1', '-fPIC', '-Ivendor\root-my-galaxy\src',
  '-DTARGET_HEADER=\"targets/m3q-S948BXXS4AZG5/target.h\"',
  'vendor\root-my-galaxy\src\main.c',
  'vendor\root-my-galaxy\src\util.c',
  'vendor\root-my-galaxy\src\slide_app.c',
  'vendor\root-my-galaxy\src\fops.c',
  'vendor\root-my-galaxy\src\pipe.c',
  'vendor\root-my-galaxy\src\root.c',
  'vendor\root-my-galaxy\src\preload.c',
  '-shared', '-pthread', '-o',
  'build\m3q-BP4A.251205.006\bin\slide_oracle.app.so'
)
$payloadArgs = @(
  '-O2', '-g0', '-Wall', '-Wextra', '-Werror',
  '-Wno-unused-parameter', '-Wno-sign-compare', '-Wno-unused-function',
  '-Isrc', '-fPIC',
  '-DTARGET_CONFIG_H=\"targets/m3q-BP4A.251205.006/target.h\"',
  'src\targets\m3q-BP4A.251205.006\main.c',
  'src\targets\m3q-BP4A.251205.006\util.c',
  'src\targets\m3q-BP4A.251205.006\slide.c',
  'src\targets\m3q-BP4A.251205.006\fops.c',
  'src\targets\m3q-BP4A.251205.006\pipe.c',
  'src\faketables.c', 'src\stage3.c',
  'src\targets\m3q-BP4A.251205.006\root.c',
  'src\app_preload.c', 'src\stage3_loop.S', 'src\stage3_poll.S',
  '-shared', '-pthread', '-o',
  'build\m3q-BP4A.251205.006\bin\preload.app.so'
)

Push-Location $exploitRoot
try {
  & $compiler @helperArgs
  if ($LASTEXITCODE -ne 0) { throw "helper build failed: $LASTEXITCODE" }
  & $compiler @oracleArgs
  if ($LASTEXITCODE -ne 0) { throw "oracle build failed: $LASTEXITCODE" }
  & $compiler @payloadArgs
  if ($LASTEXITCODE -ne 0) { throw "payload build failed: $LASTEXITCODE" }

  Get-FileHash -Algorithm SHA256 -LiteralPath @(
    'build\m3q-BP4A.251205.006\bin\su_daemon_aarch64_pie.app',
    'build\m3q-BP4A.251205.006\bin\slide_oracle.app.so',
    'build\m3q-BP4A.251205.006\bin\preload.app.so'
  ) | Format-Table -AutoSize
} finally {
  Pop-Location
}
