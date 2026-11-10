$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$venv = Join-Path $env:TEMP 'trabamap-packaging-venv'
$python = Join-Path $venv 'Scripts\python.exe'

function Test-PyInstaller {
  if (-not (Test-Path -LiteralPath $python)) { return $false }
  $previous = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  & $python -c "import PyInstaller.__main__" 2>$null | Out-Null
  $ok = $LASTEXITCODE -eq 0
  $ErrorActionPreference = $previous
  return $ok
}

# El entorno vive en la carpeta temporal y Windows puede limpiarlo a medias: si no funciona, se recrea.
if (-not (Test-PyInstaller)) {
  if (Test-Path -LiteralPath $venv) { Remove-Item -LiteralPath $venv -Recurse -Force }
  py -3 -m venv $venv
  if ($LASTEXITCODE -ne 0) { throw 'No se pudo crear el entorno de empaquetado de Python.' }
  & $python -m pip install --disable-pip-version-check 'pyinstaller==6.22.3'
  if ($LASTEXITCODE -ne 0) { throw 'No se pudo instalar PyInstaller.' }
  if (-not (Test-PyInstaller)) { throw 'PyInstaller se instaló pero no se puede importar.' }
}

$backendDir = Join-Path $root 'build\backend'
$workDir = Join-Path $root 'build\pyinstaller-work'
$specDir = Join-Path $root 'build\pyinstaller-spec'
New-Item -ItemType Directory -Force -Path $backendDir, $workDir, $specDir | Out-Null

& $python -m PyInstaller `
  --noconfirm `
  --clean `
  --onefile `
  --name TrabamapBackend `
  --distpath $backendDir `
  --workpath $workDir `
  --specpath $specDir `
  (Join-Path $root 'main.py')

if ($LASTEXITCODE -ne 0) { throw 'Falló la compilación del motor Python.' }
Write-Output "Motor empaquetado: $(Join-Path $backendDir 'TrabamapBackend.exe')"
