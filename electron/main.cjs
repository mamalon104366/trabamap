const { app, BrowserWindow, ipcMain, shell } = require('electron');
const { spawn } = require('node:child_process');
const { execFile, execFileSync } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const { identifyNetwork } = require('./discovery.cjs');
const { startDhcpListener, dhcpStatus, dhcpFor } = require('./dhcp.cjs');
const security = require('./security.cjs');

function pythonCommand() { return process.platform === 'win32' ? 'py' : 'python3'; }
function pythonArgs() { return process.platform === 'win32' ? ['-3'] : []; }
function backendLaunch(args) {
  if (app.isPackaged) {
    // El motor viaja como código Python junto a un intérprete oficial firmado (ver scripts/build-python-runtime.ps1).
    const python = path.join(process.resourcesPath, 'python', 'python.exe');
    const engine = path.join(process.resourcesPath, 'engine', 'main.py');
    if (fs.existsSync(python) && fs.existsSync(engine)) return { command: python, args: [engine, ...args], cwd: app.getPath('userData') };
    const executable = path.join(process.resourcesPath, 'backend', 'TrabamapBackend.exe');
    if (!fs.existsSync(executable)) throw new Error('Falta el motor de TrabaMap en esta instalación. Reinstala la aplicación.');
    return { command: executable, args, cwd: app.getPath('userData') };
  }
  return { command: pythonCommand(), args: [...pythonArgs(), path.join(__dirname, '..', 'main.py'), ...args], cwd: path.join(__dirname, '..') };
}
function locateNmap() {
  const candidates = [
    process.env.TRABAMAP_NMAP,
    process.env.NMAP_PATH,
    process.env.NMAP_HOME && path.join(process.env.NMAP_HOME, 'nmap.exe'),
    'C:\\Program Files (x86)\\Nmap\\nmap.exe',
    'C:\\Program Files\\Nmap\\nmap.exe',
    ...String(process.env.PATH || '').split(path.delimiter).map(directory => path.join(directory, process.platform === 'win32' ? 'nmap.exe' : 'nmap')),
  ].filter(Boolean);
  return candidates.find(candidate => {
    try { return fs.statSync(candidate).isFile(); } catch { return false; }
  }) || (process.platform === 'win32' ? 'nmap.exe' : 'nmap');
}
function locateAdb() {
  const localAppData = process.env.LOCALAPPDATA || '';
  const sdkRoots = [process.env.ANDROID_SDK_ROOT, process.env.ANDROID_HOME,
    localAppData && path.join(localAppData, 'Android', 'Sdk'),
    process.env.USERPROFILE && path.join(process.env.USERPROFILE, 'AppData', 'Local', 'Android', 'Sdk')].filter(Boolean);
  const candidates = [
    process.env.TRABAMAP_ADB,
    ...sdkRoots.flatMap(root => [path.join(root, 'platform-tools', process.platform === 'win32' ? 'adb.exe' : 'adb'), path.join(root, process.platform === 'win32' ? 'adb.exe' : 'adb')]),
    process.env.PROGRAMFILES && path.join(process.env.PROGRAMFILES, 'Android', 'Android Studio', 'platform-tools', 'adb.exe'),
    ...String(process.env.PATH || '').split(path.delimiter).map(directory => path.join(directory, process.platform === 'win32' ? 'adb.exe' : 'adb')),
  ].filter(Boolean);
  return [...new Set(candidates)].find(candidate => {
    try { return fs.statSync(candidate).isFile(); } catch { return false; }
  }) || '';
}
function runAdb(adb, args, timeout = 6000) {
  return new Promise(resolve => execFile(adb, args, {
    encoding: 'utf8', windowsHide: true, timeout, maxBuffer: 2 * 1024 * 1024,
  }, (error, stdout, stderr) => resolve({ ok: !error, stdout: stdout || '', stderr: stderr || '', error: error?.message || '' })));
}
function parseAdbProperties(text) {
  const properties = {};
  for (const line of text.split(/\r?\n/)) {
    const match = line.match(/^\[([^\]]+)\]:\s*\[([^\]]*)\]$/);
    if (match) properties[match[1]] = match[2];
  }
  return properties;
}
function adbAddress(serial) {
  const match = String(serial || '').match(/^(\d{1,3}(?:\.\d{1,3}){3}):\d+$/);
  return match?.[1] || '';
}
function parseProcMemory(text) {
  const readKb = name => Number(text.match(new RegExp(`^${name}:\\s+(\\d+)\\s+kB`, 'mi'))?.[1]) || 0;
  return { total_bytes: readKb('MemTotal') * 1024, available_bytes: readKb('MemAvailable') * 1024 };
}
function parseDataStorage(text) {
  const row = text.split(/\r?\n/).map(line => line.trim()).filter(line => line.endsWith('/data')).at(-1);
  if (!row) return { total_bytes: 0, available_bytes: 0 };
  const parts = row.split(/\s+/);
  return { total_bytes: (Number(parts[1]) || 0) * 1024, available_bytes: (Number(parts[3]) || 0) * 1024 };
}
async function androidInventory() {
  const adb = locateAdb();
  if (!adb) return { available: false, status: 'missing', path: '', devices: [], message: 'No se encontró Android Platform Tools (adb). Android solo se consulta si el teléfono ya está autorizado.' };
  const listing = await runAdb(adb, ['devices', '-l'], 5000);
  if (!listing.ok) return { available: true, status: 'error', path: adb, devices: [], message: listing.stderr.trim() || listing.error || 'ADB no pudo enumerar dispositivos.' };
  const rows = listing.stdout.split(/\r?\n/).slice(1).map(line => line.trim()).filter(Boolean).map(line => {
    const [serial, state, ...attributes] = line.split(/\s+/);
    const extra = Object.fromEntries(attributes.map(item => {
      const split = item.indexOf(':'); return split > 0 ? [item.slice(0, split), item.slice(split + 1)] : [item, ''];
    }));
    return { serial, state, model: String(extra.model || '').replaceAll('_', ' '), product: extra.product || '', device_code: extra.device || '', address: adbAddress(serial), authorized: state === 'device' };
  });
  const devices = [];
  for (const row of rows) {
    if (!row.authorized) { devices.push(row); continue; }
    const command = async args => runAdb(adb, ['-s', row.serial, ...args], 7000);
    const [propResult, memoryResult, storageResult, cpuResult, nameResult] = await Promise.all([
      command(['shell', 'getprop']), command(['shell', 'cat', '/proc/meminfo']), command(['shell', 'df', '-k', '/data']),
      command(['shell', 'cat', '/proc/cpuinfo']), command(['shell', 'settings', 'get', 'global', 'device_name']),
    ]);
    const props = parseAdbProperties(propResult.stdout);
    const memory = parseProcMemory(memoryResult.stdout);
    const storage = parseDataStorage(storageResult.stdout);
    const cpuText = cpuResult.stdout.slice(0, 12000);
    const cpuModel = cpuText.match(/^\s*(?:Hardware|model name|Processor)\s*:\s*(.+)$/mi)?.[1]?.trim() || props['ro.soc.model'] || props['ro.hardware'] || props['ro.board.platform'] || '';
    const deviceName = nameResult.stdout.trim();
    devices.push({
      ...row,
      manufacturer: props['ro.product.manufacturer'] || props['ro.product.brand'] || '',
      brand: props['ro.product.brand'] || '', model: props['ro.product.model'] || row.model || '',
      android_version: props['ro.build.version.release'] || '', android_sdk: props['ro.build.version.sdk'] || '',
      build: props['ro.build.display.id'] || '', security_patch: props['ro.build.version.security_patch'] || '',
      device_name: deviceName && !['null', 'unknown'].includes(deviceName.toLowerCase()) ? deviceName : '',
      cpu_model: cpuModel, cpu_architecture: props['ro.product.cpu.abi'] || props['ro.product.cpu.abi2'] || '',
      ram_total_bytes: memory.total_bytes, ram_available_bytes: memory.available_bytes,
      storage_total_bytes: storage.total_bytes, storage_available_bytes: storage.available_bytes,
      source: 'Android consultado mediante ADB ya autorizado',
      data_available: Boolean(propResult.ok || memoryResult.ok || storageResult.ok),
    });
  }
  const authorized = devices.filter(device => device.authorized).length;
  return { available: true, status: authorized ? 'connected' : rows.length ? 'permission-required' : 'not-paired', path: adb, devices, message: authorized ? `${authorized} dispositivo(s) Android ya autorizado(s) por ADB.` : rows.length ? 'ADB detectó dispositivos, pero ninguno autorizó el acceso de depuración.' : 'ADB está disponible, pero no hay teléfonos conectados o emparejados.' };
}
function paths() {
  const portableDirectory = process.env.PORTABLE_EXECUTABLE_DIR;
  let base = portableDirectory ? path.join(portableDirectory, 'TrabamapData') : app.getPath('userData');
  if (portableDirectory) {
    try { fs.mkdirSync(base, { recursive: true }); }
    catch { base = app.getPath('userData'); }
  }
  return { base, reports: path.join(base, 'reports'), logs: path.join(base, 'activity.jsonl'), settings: path.join(base, 'security.json'), dhcp: path.join(base, 'dhcp-seen.json') };
}
function appendLog(event) {
  const p = paths(); fs.mkdirSync(p.base, { recursive: true });
  fs.appendFileSync(p.logs, `${JSON.stringify({ time: new Date().toISOString(), ...event })}\n`, 'utf8');
}
function readLogs() {
  const file = paths().logs;
  if (!fs.existsSync(file)) return [];
  return fs.readFileSync(file, 'utf8').split(/\r?\n/).filter(Boolean).slice(-250).reverse().map(line => { try { return JSON.parse(line); } catch { return null; } }).filter(Boolean);
}
function runBackend(...args) {
  return new Promise((resolve, reject) => {
    const p = paths(); fs.mkdirSync(p.reports, { recursive: true });
    const launch = backendLaunch(args);
    const child = spawn(launch.command, launch.args, {
      cwd: launch.cwd, windowsHide: true,
      env: { ...process.env, TRABAMAP_REPORTS: p.reports, TRABAMAP_NMAP: locateNmap(), PYTHONUTF8: '1' }
    });
    let out = '', err = '';
    child.stdout.on('data', b => out += b.toString()); child.stderr.on('data', b => err += b.toString());
    child.on('error', e => reject(new Error(`No se pudo iniciar el motor local: ${e.message}`)));
    child.on('close', code => {
      if (code !== 0) { try { reject(new Error(JSON.parse(err).error || err)); } catch { reject(new Error(err.trim() || `Python terminó con código ${code}`)); } return; }
      try { resolve(JSON.parse(out)); } catch { reject(new Error(err.trim() || 'Respuesta inválida del motor Python.')); }
    });
  });
}
function runBackendInput(...argsAndInput) {
  const input = argsAndInput.pop();
  const args = argsAndInput;
  return new Promise((resolve, reject) => {
    const p = paths(); fs.mkdirSync(p.reports, { recursive: true });
    const launch = backendLaunch(args);
    const child = spawn(launch.command, launch.args, {
      cwd: launch.cwd, windowsHide: true,
      env: { ...process.env, TRABAMAP_REPORTS: p.reports, TRABAMAP_NMAP: locateNmap(), PYTHONUTF8: '1' },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let out = '', err = '';
    child.stdout.on('data', b => out += b.toString()); child.stderr.on('data', b => err += b.toString());
    child.on('error', e => reject(new Error(`No se pudo iniciar el motor local: ${e.message}`)));
    child.on('close', code => {
      if (code !== 0) { try { reject(new Error(JSON.parse(err).error || err)); } catch { reject(new Error(err.trim() || `Python terminó con código ${code}`)); } return; }
      try { resolve(JSON.parse(out)); } catch { reject(new Error(err.trim() || 'Respuesta inválida del motor Python.')); }
    });
    child.stdin.on('error', () => {});
    child.stdin.end(input, 'utf8');
  });
}
function localInterfaces() {
  const networkCidr = (address, cidr) => {
    const [ip, prefixText] = String(cidr || '').split('/');
    const prefix = Number(prefixText);
    const octets = ip.split('.').map(Number);
    if (octets.length !== 4 || octets.some(value => !Number.isInteger(value) || value < 0 || value > 255) || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) return '';
    const value = octets.reduce((sum, part) => ((sum << 8) | part) >>> 0, 0);
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    const start = (value & mask) >>> 0;
    return [24, 16, 8, 0].map(shift => (start >>> shift) & 255).join('.') + `/${prefix}`;
  };
  const rows = Object.entries(os.networkInterfaces()).flatMap(([name, addrs]) => (addrs || [])
    .filter(a => (a.family === 'IPv4' || a.family === 4) && !a.internal && !a.address.startsWith('169.254.'))
    .map(a => ({ name, address: a.address, netmask: a.netmask, cidr: a.cidr, network: networkCidr(a.address, a.cidr) })));
  const privateRank = a => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(a.address) ? 0 : 1;
  rows.sort((a, b) => privateRank(a) - privateRank(b));
  return rows;
}
function runPowerShellJson(script) {
  return new Promise(resolve => {
    execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], {
      encoding: 'utf8', windowsHide: true, timeout: 12000, maxBuffer: 2 * 1024 * 1024,
    }, (error, stdout) => {
      if (error || !stdout.trim()) { resolve(null); return; }
      try { resolve(JSON.parse(stdout.trim())); } catch { resolve(null); }
    });
  });
}
async function localInventory() {
  const interfaces = Object.entries(os.networkInterfaces()).flatMap(([name, rows]) => (rows || [])
    .filter(item => !item.internal && !item.address.startsWith('169.254.'))
    .map(item => ({ name, address: item.address })));
  const cpuRows = os.cpus();
  const fallback = {
    platform: process.platform,
    os_name: `${os.type()} ${os.release()}`,
    os_version: os.release(),
    architecture: os.arch(),
    computer_name: os.hostname(),
    user_name: (() => { try { return os.userInfo().username; } catch { return ''; } })(),
    ram_total_bytes: os.totalmem(),
    ram_free_bytes: os.freemem(),
    cpu: cpuRows[0] ? [{ name: cpuRows[0].model, logical_processors: cpuRows.length }] : [],
    memory_modules: [], motherboard: [], gpu: [], storage: [], tcp_listeners: [], local_addresses: interfaces,
    source: 'Datos locales del sistema operativo',
  };
  if (process.platform !== 'win32') return fallback;
  const script = String.raw`
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$osInfo = Get-CimInstance Win32_OperatingSystem
$computer = Get-CimInstance Win32_ComputerSystem
$processors = @(Get-CimInstance Win32_Processor | ForEach-Object { [pscustomobject]@{ name=$_.Name; manufacturer=$_.Manufacturer; cores=[int]$_.NumberOfCores; logical_processors=[int]$_.NumberOfLogicalProcessors; max_clock_mhz=[int]$_.MaxClockSpeed } })
$memory = @(Get-CimInstance Win32_PhysicalMemory | ForEach-Object { [pscustomobject]@{ capacity_bytes=[long]$_.Capacity; speed_mhz=[int]$_.Speed; configured_speed_mhz=[int]$_.ConfiguredClockSpeed; manufacturer=$_.Manufacturer; part_number=$_.PartNumber } })
$boards = @(Get-CimInstance Win32_BaseBoard | ForEach-Object { [pscustomobject]@{ manufacturer=$_.Manufacturer; product=$_.Product } })
$graphics = @(Get-CimInstance Win32_VideoController | ForEach-Object { [pscustomobject]@{ name=$_.Name; driver_version=$_.DriverVersion } })
$drives = @(Get-CimInstance Win32_DiskDrive | ForEach-Object { [pscustomobject]@{ model=$_.Model; size_bytes=[long]$_.Size; interface_type=$_.InterfaceType } })
$processes = @{}
Get-Process | ForEach-Object { $processes[[int]$_.Id] = $_ }
$connections = @()
if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) { $connections = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue) }
$listeners = @($connections | ForEach-Object {
  $process = $processes[[int]$_.OwningProcess]
  [pscustomobject]@{ port=[int]$_.LocalPort; protocol='TCP'; address=[string]$_.LocalAddress; pid=[int]$_.OwningProcess; application=$(if ($process) { $process.ProcessName } else { 'Proceso sin identificar' }) }
} | Sort-Object port,address,pid -Unique)
$caption = [string]$osInfo.Caption
$build = [int]$osInfo.BuildNumber
if ($build -ge 22000) { $caption = $caption -replace 'Windows 10', 'Windows 11' }
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$payload = [ordered]@{
  platform='win32'; os_name=$caption -replace '^Microsoft\s+', ''; os_version=[string]$osInfo.Version; os_build=[string]$osInfo.BuildNumber; architecture=[string]$osInfo.OSArchitecture; user_name=$user; computer_name=[string]$computer.Name
  computer_manufacturer=[string]$computer.Manufacturer; computer_model=[string]$computer.Model
  ram_total_bytes=[long]$computer.TotalPhysicalMemory; ram_free_bytes=([long]$osInfo.FreePhysicalMemory * 1KB)
  cpu=$processors; memory_modules=$memory; motherboard=$boards; gpu=$graphics; storage=$drives; tcp_listeners=$listeners
  source='Windows CIM y procesos locales'
}
ConvertTo-Json -InputObject $payload -Depth 7 -Compress
`;
  const windowsData = await runPowerShellJson(script);
  if (!windowsData || typeof windowsData !== 'object') return fallback;
  for (const field of ['cpu', 'memory_modules', 'motherboard', 'gpu', 'storage', 'tcp_listeners']) {
    if (!Array.isArray(windowsData[field])) windowsData[field] = windowsData[field] ? [windowsData[field]] : [];
  }
  return { ...fallback, ...windowsData, local_addresses: interfaces };
}
function defaultGateway() {
  try {
    if (process.platform === 'win32') {
      const output = execFileSync('route.exe', ['print', '-4'], { encoding: 'utf8', windowsHide: true, timeout: 2500 });
      const row = output.split(/\r?\n/).map(line => line.trim().split(/\s+/)).find(parts => parts[0] === '0.0.0.0' && parts[1] === '0.0.0.0' && /^\d{1,3}(?:\.\d{1,3}){3}$/.test(parts[2] || ''));
      return row?.[2] || '';
    }
    if (process.platform === 'darwin') {
      const output = execFileSync('route', ['-n', 'get', 'default'], { encoding: 'utf8', timeout: 2500 });
      return output.match(/^\s*gateway:\s*(\S+)/m)?.[1] || '';
    }
    const output = execFileSync('ip', ['-4', 'route', 'show', 'default'], { encoding: 'utf8', timeout: 2500 });
    return output.match(/(?:^|\s)via\s+(\S+)/)?.[1] || '';
  } catch { return ''; }
}
function createWindow() {
  const win = new BrowserWindow({ width: 1720, height: 1080, minWidth: 840, minHeight: 620, backgroundColor: '#0b0b0e', title: 'TrabaMap', show: false, icon: app.isPackaged ? path.join(process.resourcesPath, 'trabamap.ico') : path.join(__dirname, '..', 'build', 'trabamap.ico'), autoHideMenuBar: true,
    webPreferences: { preload: path.join(__dirname, 'preload.cjs'), contextIsolation: true, nodeIntegration: false, sandbox: true } });
  win.once('ready-to-show', () => { win.maximize(); win.show(); });
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith('https://nmap.org/')) shell.openExternal(url);
    return { action: 'deny' };
  });
  // La ventana solo muestra la interfaz propia: ningún enlace puede reemplazarla por otra página.
  win.webContents.on('will-navigate', (event, url) => {
    if (url === win.webContents.getURL()) return;
    event.preventDefault();
    if (url.startsWith('https://nmap.org/')) shell.openExternal(url);
  });
  if (app.isPackaged) win.loadFile(path.join(__dirname, '..', 'dist', 'index.html'));
  else win.loadURL(process.env.TRABAMAP_DEV_URL || 'http://127.0.0.1:5173');
  win.on('closed', () => { if (mainWindow === win) mainWindow = null; });
  mainWindow = win;
}

let mainWindow = null;
const activeScans = new Map();
ipcMain.handle('tmap:system', async () => {
  const interfaces = localInterfaces();
  // Cada fuente falla por separado: sin Python o sin Nmap la interfaz sigue mostrando la red local.
  const settled = await Promise.allSettled([runBackend('system-json'), localInventory(), androidInventory()]);
  const engine = settled[0].status === 'fulfilled' ? settled[0].value : { nmap: 'No disponible', nmap_path: null, engine_error: settled[0].reason?.message || 'No se pudo iniciar el motor local.' };
  const inventory = settled[1].status === 'fulfilled' ? settled[1].value : null;
  const android = settled[2].status === 'fulfilled' ? settled[2].value : { available: false, status: 'error', devices: [], message: 'No se pudo consultar ADB.' };
  const active = interfaces[0];
  return { ...engine, dhcp_listener: dhcpStatus(), security: security.loadSettings(paths().settings), interfaces, local_inventory: inventory, adb_inventory: android, gateway: defaultGateway(), network_cidr: active?.network || active?.cidr || '', local_ip: active?.address || engine.local_ip || '127.0.0.1', hostname: os.hostname() };
});
ipcMain.handle('tmap:reports', () => runBackend('reports-json'));
ipcMain.handle('tmap:policy-check', (_event, request) => security.evaluate(String(request?.target || ''), request?.options || {}, security.loadSettings(paths().settings)));
ipcMain.handle('tmap:settings-get', () => security.loadSettings(paths().settings));
ipcMain.handle('tmap:settings-set', (_event, value) => {
  if (!value || typeof value !== 'object') throw new Error('Configuración de seguridad inválida.');
  fs.mkdirSync(paths().base, { recursive: true });
  const before = security.loadSettings(paths().settings);
  const saved = security.saveSettings(paths().settings, value);
  const changes = Object.keys(saved).filter(key => saved[key] !== before[key]).map(key => `${key}: ${before[key]} → ${saved[key]}`);
  if (changes.length) appendLog({ type: 'security', target: 'Parámetros de seguridad', message: `Cambio de configuración · ${changes.join(' · ')}` });
  return saved;
});
ipcMain.handle('tmap:identify', async (_event, request) => {
  // Solo se consulta desde una interfaz local real de este equipo y hacia direcciones privadas.
  const local = localInterfaces().find(item => item.address === request?.localAddress);
  if (!local || !Array.isArray(request.addresses)) return { devices: {}, sources: { mdns: 0, upnp: 0, ttl: 0 } };
  const result = await identifyNetwork(local.address, request.addresses);
  // Lo que cada equipo dijo de sí mismo al pedir su dirección IP (escucha DHCP).
  const macs = request.macs && typeof request.macs === 'object' ? request.macs : {};
  let fromDhcp = 0;
  for (const address of request.addresses) {
    const record = typeof address === 'string' ? dhcpFor(address, typeof macs[address] === 'string' ? macs[address] : '') : null;
    if (!record) continue;
    result.devices[address] = { mdns: null, upnp: null, ttl: null, ...(result.devices[address] || {}), dhcp: { hostname: record.hostname, vendor_class: record.vendor_class, params: record.params, seen_at: record.seen_at } };
    fromDhcp += 1;
  }
  result.sources.dhcp = fromDhcp;
  appendLog({ type: 'identify', target: local.network || local.address, message: `Identificación pasiva: ${result.sources.mdns} por mDNS, ${result.sources.upnp} por UPnP, ${result.sources.ttl} respondieron al ping, ${fromDhcp} vistos por DHCP` });
  return result;
});
ipcMain.handle('tmap:logs', () => readLogs());
ipcMain.handle('tmap:report', async (_event, name) => {
  if (typeof name !== 'string' || path.basename(name) !== name || !name.endsWith('.json')) throw new Error('Nombre de reporte inválido.');
  const file = path.join(paths().reports, name);
  if (!fs.existsSync(file)) throw new Error('El reporte ya no existe.');
  return JSON.parse(fs.readFileSync(file, 'utf8'));
});
ipcMain.handle('tmap:open-report', async (_event, name) => {
  if (typeof name !== 'string' || path.basename(name) !== name || !/\.(json|xml|xlsx)$/.test(name)) throw new Error('Archivo de reporte inválido.');
  const file = path.join(paths().reports, name);
  if (!fs.existsSync(file)) throw new Error('El reporte ya no existe.');
  await shell.openPath(file); return true;
});
ipcMain.handle('tmap:export-excel', async (_event, report) => {
  if (!report || typeof report !== 'object' || !Array.isArray(report.hosts) || typeof report.target !== 'string') throw new Error('El resultado no tiene datos de escaneo para exportar.');
  let payload;
  try { payload = JSON.stringify(report); } catch { throw new Error('No se pudo preparar la evidencia para Excel.'); }
  if (Buffer.byteLength(payload, 'utf8') > 24 * 1024 * 1024) throw new Error('El reporte es demasiado grande para exportarlo de una sola vez.');
  const result = await runBackendInput('export-xlsx-stdin', payload);
  if (typeof result?.name !== 'string' || path.basename(result.name) !== result.name || !result.name.endsWith('.xlsx')) throw new Error('Python no devolvió un archivo Excel válido.');
  const file = path.join(paths().reports, result.name);
  if (!fs.existsSync(file)) throw new Error('No se encontró el Excel generado.');
  const openError = await shell.openPath(file);
  return { name: result.name, path: file, openError: openError || '' };
});
ipcMain.handle('tmap:scan', async (event, opts) => {
  if (!opts || typeof opts.target !== 'string' || opts.target.length > 2048) throw new Error('Escribe una IP, red o nombre de host.');
  if (!opts.options || typeof opts.options !== 'object') throw new Error('Selecciona las opciones del escaneo.');
  // Parámetros de seguridad: se comprueban aquí, fuera del alcance de la ventana.
  const verdict = security.evaluate(opts.target, opts.options, security.loadSettings(paths().settings));
  if (verdict.blocked.length) { appendLog({ type: 'scan-blocked', target: opts.target, message: verdict.blocked[0] }); throw new Error(verdict.blocked.join(' ')); }
  const acknowledged = Array.isArray(opts.acknowledged) ? opts.acknowledged : [];
  const pending = verdict.needs.filter(item => !acknowledged.includes(item.code));
  if (pending.length) { appendLog({ type: 'scan-blocked', target: opts.target, message: `Falta confirmar: ${pending.map(item => item.title).join('; ')}` }); throw new Error(`Este escaneo necesita tu confirmación: ${pending.map(item => item.title).join('; ')}.`); }
  const audit = { user: (() => { try { return os.userInfo().username; } catch { return ''; } })(), options: opts.options, confirmations: verdict.needs.map(item => item.code) };
  const sender = event.sender; const id = sender.id; const started = Date.now();
  const logTarget = opts.options.profile === 'signature' ? `${opts.target.split(/\s+/).length} equipos (puertos firma)` : opts.target;
  appendLog({ type: 'scan-start', target: logTarget, profile: opts.options.profile || 'personalizado', message: verdict.needs.length ? `Escaneo iniciado · el usuario confirmó: ${verdict.needs.map(item => item.title).join('; ')}` : 'Escaneo iniciado', ...audit });
  return new Promise((resolve, reject) => {
    const p = paths(); fs.mkdirSync(p.reports, { recursive: true });
    const launch = backendLaunch(['desktop-scan', opts.target, JSON.stringify(opts.options)]);
    const child = spawn(launch.command, launch.args, {
      cwd: launch.cwd, windowsHide: true,
      env: { ...process.env, TRABAMAP_REPORTS: p.reports, TRABAMAP_NMAP: locateNmap(), PYTHONUTF8: '1' }
    });
    activeScans.set(id, { child, target: logTarget, cancelled: false });
    let buffer = '', stderr = '';
    child.stdout.on('data', chunk => {
      buffer += chunk.toString(); const lines = buffer.split(/\r?\n/); buffer = lines.pop();
      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const payload = JSON.parse(line);
          if (payload.event === 'progress') { if (!sender.isDestroyed()) sender.send('tmap:scan-progress', payload); }
          else if (payload.target && payload.summary) child.scanResult = payload;
        } catch { /* Ignore partial or diagnostic lines; Python reports failures on stderr. */ }
      }
    });
    child.stderr.on('data', chunk => stderr += chunk.toString());
    child.on('error', e => { activeScans.delete(id); appendLog({ type: 'scan-error', target: logTarget, message: e.message }); reject(new Error(`No se pudo iniciar el motor local: ${e.message}`)); });
    child.on('close', code => {
      const wasCancelled = activeScans.get(id)?.cancelled;
      activeScans.delete(id);
      if (buffer.trim()) { try { const parsed = JSON.parse(buffer); if (parsed.target && parsed.summary) child.scanResult = parsed; } catch {} }
      const active = !sender.isDestroyed();
      if (wasCancelled) { if (active) reject(new Error('Escaneo cancelado.')); return; }
      if (code === 0 && child.scanResult) {
        const result = child.scanResult;
        const message = result.scan_type === 'ping'
          ? `Descubrimiento terminado: ${result.summary.hosts} equipos respondieron`
          : `Escaneo terminado: ${result.summary.open_ports} puertos abiertos`;
        appendLog({ type: 'scan-complete', target: logTarget, elapsed_ms: Date.now() - started, summary: result.summary, message });
        if (active) resolve(result); else resolve(null);
      } else {
        const rawError = stderr.trim();
        let reason = rawError || (code === 1 ? 'Nmap no pudo completar el escaneo.' : `El proceso terminó con código ${code}.`);
        try { reason = JSON.parse(reason).error || reason; }
        catch { if (reason.includes('Traceback (most recent call last)')) reason = reason.split(/\r?\n/).filter(Boolean).at(-1) || 'Falló el motor de Python.'; }
        appendLog({ type: 'scan-error', target: logTarget, elapsed_ms: Date.now() - started, message: reason });
        reject(new Error(reason));
      }
    });
  });
});
ipcMain.handle('tmap:cancel-scan', async event => {
  const active = activeScans.get(event.sender.id); if (!active) return false;
  active.cancelled = true;
  if (process.platform === 'win32') {
    const killer = spawn('taskkill.exe', ['/PID', String(active.child.pid), '/T', '/F'], { windowsHide: true, stdio: 'ignore' });
    killer.on('error', () => active.child.kill());
  } else active.child.kill('SIGTERM');
  appendLog({ type: 'scan-cancel', target: active.target, message: 'Escaneo cancelado por el usuario' });
  return true;
});

const hasSingleInstance = app.requestSingleInstanceLock();
if (!hasSingleInstance) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.focus();
    }
  });
  app.whenReady().then(() => {
    startDhcpListener(paths().dhcp);
    createWindow();
    app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
  });
}
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
