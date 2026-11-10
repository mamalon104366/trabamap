# Prepara el intérprete de Python que viaja dentro de TrabaMap.
#
# Se copia el Python oficial ya instalado (firmado por la Python Software Foundation) en lugar de
# compilar un .exe propio: un ejecutable sin firma lo bloquea el Control inteligente de aplicaciones
# de Windows 11, mientras que python.exe firmado + los .py del motor se ejecutan sin problema.
# La licencia de Python (PSF) permite redistribuirlo.
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$source = (py -3 -c "import sys; print(sys.base_prefix)").Trim()
if (-not (Test-Path -LiteralPath (Join-Path $source 'python.exe'))) { throw "No se encontró una instalación de Python en $source." }
$version = (py -3 -c "import sys; print(f'{sys.version_info.major}{sys.version_info.minor}')").Trim()
$target = Join-Path $root 'build\python-runtime'

if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Recurse -Force }
New-Item -ItemType Directory -Force -Path $target | Out-Null

foreach ($file in @('python.exe', 'python3.dll', "python$version.dll", 'vcruntime140.dll', 'vcruntime140_1.dll', 'LICENSE.txt')) {
  $path = Join-Path $source $file
  if (Test-Path -LiteralPath $path) { Copy-Item -LiteralPath $path -Destination $target }
}

# Extensiones compiladas (firmadas); se omite Tcl/Tk porque el motor no tiene interfaz gráfica.
robocopy (Join-Path $source 'DLLs') (Join-Path $target 'DLLs') /E /NFL /NDL /NJH /NJS /NP /XF '_tkinter.pyd' 'tcl*.dll' 'tk*.dll' 'zlib1.dll.bak' | Out-Null
if ($LASTEXITCODE -ge 8) { throw 'No se pudieron copiar las extensiones de Python.' }

# Biblioteca estándar sin paquetes de terceros, pruebas ni herramientas de escritorio.
robocopy (Join-Path $source 'Lib') (Join-Path $target 'Lib') /E /NFL /NDL /NJH /NJS /NP `
  /XD 'site-packages' 'test' 'tests' 'idlelib' 'tkinter' 'turtledemo' 'ensurepip' 'venv' 'pydoc_data' '__pycache__' 'idle_test' `
  /XF '*.pyc' 'turtle.py' | Out-Null
if ($LASTEXITCODE -ge 8) { throw 'No se pudo copiar la biblioteca estándar de Python.' }
$global:LASTEXITCODE = 0

# Modo aislado: este Python solo ve su propia biblioteca y el motor de TrabaMap (..\engine),
# sin leer variables de entorno, el registro ni paquetes instalados en el equipo.
Set-Content -LiteralPath (Join-Path $target "python$version._pth") -Value @('Lib', 'DLLs', '..\engine') -Encoding ascii

$signature = Get-AuthenticodeSignature (Join-Path $target 'python.exe')
$size = [Math]::Round(((Get-ChildItem $target -Recurse -File | Measure-Object Length -Sum).Sum / 1MB), 1)
Write-Output "Python $version preparado en $target ($size MB). Firma de python.exe: $($signature.Status)"
if ($signature.Status -ne 'Valid') { Write-Warning 'python.exe no tiene una firma válida: Windows podría bloquearlo en equipos con Control inteligente de aplicaciones.' }
