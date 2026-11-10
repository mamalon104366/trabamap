// Instalación asistida de Nmap.
//
// La licencia de Nmap (NPSL, sección 10) no permite redistribuir sus instaladores oficiales de Windows porque
// incluyen Npcap. Por eso TrabaMap no los lleva dentro: cuando el usuario lo pide, descarga el instalador
// oficial directamente desde nmap.org, comprueba que está firmado por Nmap Software LLC y lo abre. El usuario
// acepta las licencias de Nmap y Npcap en el propio instalador, igual que si lo hubiera bajado a mano.
const https = require('node:https');
const fs = require('node:fs');
const path = require('node:path');
const { execFile } = require('node:child_process');

const HOST = 'nmap.org';
const MAX_BYTES = 150 * 1024 * 1024;
const SIGNER = 'Nmap Software LLC';

function get(pathname, onResponse) {
  return new Promise((resolve, reject) => {
    const request = https.get({ host: HOST, path: pathname, headers: { 'User-Agent': 'TrabaMap' }, timeout: 20000 }, response => {
      // Solo se aceptan respuestas directas de nmap.org: ninguna redirección a otro servidor.
      if (response.statusCode !== 200) { response.resume(); reject(new Error(`nmap.org respondió ${response.statusCode}.`)); return; }
      onResponse(response, resolve, reject);
    });
    request.on('timeout', () => request.destroy(new Error('nmap.org no respondió a tiempo.')));
    request.on('error', error => reject(new Error(`No se pudo conectar con nmap.org: ${error.message}`)));
  });
}

/** Lee la página oficial de descargas y devuelve el instalador estable más reciente para Windows. */
async function latestInstaller() {
  const html = await get('/download.html', (response, resolve, reject) => {
    let body = '';
    response.setEncoding('utf8');
    response.on('data', chunk => { body += chunk; if (body.length > 2_000_000) { response.destroy(); reject(new Error('La página de descargas es más grande de lo esperado.')); } });
    response.on('end', () => resolve(body));
  });
  const versions = [...html.matchAll(/\/dist\/nmap-(\d+(?:\.\d+)+)-setup\.exe/g)].map(match => match[1]);
  if (!versions.length) throw new Error('No se encontró el instalador de Windows en nmap.org. Descárgalo manualmente desde https://nmap.org/download.html');
  const newest = versions.sort((a, b) => a.localeCompare(b, undefined, { numeric: true })).at(-1);
  return { version: newest, file: `nmap-${newest}-setup.exe`, path: `/dist/nmap-${newest}-setup.exe`, url: `https://${HOST}/dist/nmap-${newest}-setup.exe` };
}

function download(installer, folder, onProgress) {
  fs.mkdirSync(folder, { recursive: true });
  const target = path.join(folder, installer.file);
  return get(installer.path, (response, resolve, reject) => {
    const total = Number(response.headers['content-length']) || 0;
    if (total > MAX_BYTES) { response.destroy(); reject(new Error('El instalador es más grande de lo esperado.')); return; }
    const file = fs.createWriteStream(target);
    let received = 0;
    response.on('data', chunk => {
      received += chunk.length;
      if (received > MAX_BYTES) { response.destroy(); file.destroy(); reject(new Error('El instalador es más grande de lo esperado.')); return; }
      onProgress?.({ received, total, percent: total ? Math.round(received * 100 / total) : null });
    });
    response.pipe(file);
    file.on('finish', () => file.close(() => resolve(target)));
    file.on('error', error => reject(new Error(`No se pudo guardar el instalador: ${error.message}`)));
  });
}

/** Comprueba la firma digital del archivo con Windows; solo vale una firma válida de Nmap Software LLC. */
function verifySignature(file) {
  return new Promise(resolve => {
    const script = `$s = Get-AuthenticodeSignature -LiteralPath $env:TRABAMAP_FILE; [Console]::Out.Write(($s.Status.ToString()) + '|' + $s.SignerCertificate.Subject)`;
    execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], { encoding: 'utf8', windowsHide: true, timeout: 30000, env: { ...process.env, TRABAMAP_FILE: file } }, (error, stdout) => {
      const [status, subject = ''] = String(stdout || '').trim().split('|');
      const signer = subject.match(/CN=([^,]+)/)?.[1] || '';
      resolve({ valid: !error && status === 'Valid' && signer === SIGNER, status: status || 'Desconocido', signer });
    });
  });
}

/**
 * Descarga, verifica y abre el instalador oficial.
 * @param open función que abre el archivo (shell.openPath); se inyecta para poder probar el resto sin Electron.
 */
async function installNmap({ folder, onProgress, open }) {
  if (process.platform !== 'win32') throw new Error('La instalación asistida solo está disponible en Windows. En Linux o macOS instala Nmap con el gestor de paquetes.');
  onProgress?.({ stage: 'buscar', message: 'Buscando la última versión en nmap.org…' });
  const installer = await latestInstaller();
  onProgress?.({ stage: 'descargar', message: `Descargando Nmap ${installer.version} desde nmap.org…`, percent: 0 });
  const file = await download(installer, folder, progress => onProgress?.({ stage: 'descargar', message: `Descargando Nmap ${installer.version} desde nmap.org…`, percent: progress.percent }));
  onProgress?.({ stage: 'verificar', message: 'Comprobando la firma digital del instalador…' });
  const signature = await verifySignature(file);
  if (!signature.valid) {
    fs.rmSync(file, { force: true });
    throw new Error(`El archivo descargado no tiene una firma válida de ${SIGNER} (estado: ${signature.status}). Se eliminó por seguridad.`);
  }
  onProgress?.({ stage: 'abrir', message: 'Abriendo el instalador oficial de Nmap…' });
  const failure = await open(file);
  if (failure) throw new Error(`Windows no pudo abrir el instalador: ${failure}`);
  return { version: installer.version, file, signer: signature.signer };
}

module.exports = { installNmap, latestInstaller, verifySignature, SIGNER };
