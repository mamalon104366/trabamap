// Empaqueta TrabaMap para Windows.
//
// Deja en artifacts/windows:
//   1. TrabaMap-<versión>-win-x64.zip → carpeta lista para descomprimir y abrir. No contiene ningún
//      ejecutable modificado, así que también funciona en equipos con el Control inteligente de
//      aplicaciones de Windows 11. A cambio, Windows la lista como "Electron" en el Administrador de tareas.
//   2. TrabaMap-Instalador-…exe y TrabaMap-Portable-…exe → llevan el nombre "TrabaMap" y su icono grabados
//      en el ejecutable (Administrador de tareas, barra de tareas y accesos directos). Al no estar firmados,
//      Windows avisa con SmartScreen y los bloquea donde el Control inteligente de aplicaciones esté activo.
//
// Todo se arma en una carpeta de trabajo aparte, para poder empaquetar aunque TrabaMap esté abierto.
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const out = path.join(root, 'artifacts', 'windows');
const work = path.join(root, 'artifacts', 'trabajo');
const version = require(path.join(root, 'package.json')).version;
const node = process.execPath;
const builder = path.join(root, 'node_modules', 'electron-builder', 'cli.js');
const output = `-c.directories.output=${work}`;

function run(label, command, args, { optional = false } = {}) {
  console.log(`\n▶ ${label}`);
  const result = spawnSync(command, args, { cwd: root, stdio: 'inherit', windowsHide: true });
  if (result.status === 0) return true;
  if (optional) { console.warn(`  (omitido) ${label}: ${result.error?.message || `código ${result.status}`}`); return false; }
  console.error(`✖ Falló: ${label}`);
  process.exit(result.status || 1);
}
function publish(name) {
  const source = path.join(work, name);
  if (!fs.existsSync(source)) return false;
  fs.mkdirSync(out, { recursive: true });
  fs.copyFileSync(source, path.join(out, name));
  return true;
}

run('Compilar la interfaz', node, [path.join(root, 'node_modules', 'vite', 'bin', 'vite.js'), 'build']);
run('Preparar Python firmado', 'powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', path.join(root, 'scripts', 'build-python-runtime.ps1')]);
fs.rmSync(work, { recursive: true, force: true });

// 1) Carpeta compatible: el ejecutable de Electron queda tal como lo publica el proyecto Electron.
run('Armar la carpeta compatible', node, [builder, '--win', 'dir', '--x64', output, '-c.win.signAndEditExecutable=false']);
const zipName = `TrabaMap-${version}-win-x64.zip`;
fs.renameSync(path.join(work, 'win-unpacked'), path.join(work, 'TrabaMap'));
// El tar de Windows (bsdtar) crea .zip con -a; el de Git no entiende rutas con letra de unidad.
const zipped = run('Comprimir la carpeta (.zip)', path.join(process.env.SystemRoot || 'C:/Windows', 'System32', 'tar.exe'), ['-a', '-c', '-f', path.join(work, zipName), '-C', work, 'TrabaMap'], { optional: true });
fs.rmSync(path.join(work, 'TrabaMap'), { recursive: true, force: true });
if (!zipped || !publish(zipName)) { console.error('✖ No se pudo crear el .zip.'); process.exit(1); }

// 2) Instalador y portable con la marca grabada en el ejecutable.
const branded = [builder, '--win', 'nsis', 'portable', '--x64', output, '-c.win.signAndEditExecutable=true'];
if (!run('Crear instalador y portable con marca (.exe)', node, branded, { optional: true })) {
  run('Crear instalador y portable con marca (.exe), segundo intento', node, branded, { optional: true });
}
for (const name of [`TrabaMap-Instalador-${version}-x64.exe`, `TrabaMap-Instalador-${version}-x64.exe.blockmap`, `TrabaMap-Portable-${version}-x64.exe`]) publish(name);

// La carpeta suelta con marca se deja disponible para pruebas locales si no hay una versión abierta.
try {
  fs.rmSync(path.join(out, 'win-unpacked'), { recursive: true, force: true });
  fs.renameSync(path.join(work, 'win-unpacked'), path.join(out, 'win-unpacked'));
} catch { console.warn('  (aviso) artifacts/windows/win-unpacked está en uso y no se actualizó; cierra TrabaMap y vuelve a empaquetar si la necesitas.'); }
fs.rmSync(work, { recursive: true, force: true });

console.log('\nListo. Archivos generados:');
for (const name of fs.readdirSync(out)) {
  const file = path.join(out, name);
  if (fs.statSync(file).isFile() && /\.(zip|exe)$/.test(name)) console.log(`  ${name}  ·  ${(fs.statSync(file).size / 1048576).toFixed(0)} MB`);
}
