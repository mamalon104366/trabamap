// Datos de ejemplo para revisar la interfaz sin Electron: `npm run dev` y abrir /?demo.
// Solo se carga en desarrollo (ver src/boot.js); no se incluye en la aplicación empaquetada.
const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
const listeners = new Set();
let cancelled = false;

const port = (number, service, product, version, state, name, description, risk, recommendation) => ({
  port: number, protocol: 'tcp', state, reason: state === 'open' ? 'syn-ack' : 'no-response', service, product, version, cpe: [], scripts: [],
  name, description, risk, recommendation, application: [product, version].filter(Boolean).join(' ') || service,
  application_source: 'Producto/version reportado por la huella de servicio de Nmap (-sV).',
});
const demoPorts = [
  port(23, 'telnet', 'BusyBox telnetd', '1.31', 'open', 'Telnet', 'Acceso remoto antiguo que envía todo, incluidas contraseñas, sin cifrar.', 'Muy alto', 'Desactívalo y usa SSH.'),
  port(445, 'microsoft-ds', 'Samba smbd', '4.15', 'open', 'SMB', 'Compartición de archivos e impresoras en Windows.', 'Alto', 'No lo expongas a Internet; limita SMB al segmento de confianza.'),
  port(22, 'ssh', 'OpenSSH', '9.6', 'open', 'SSH', 'Acceso remoto seguro a una consola; habitual en administración de servidores.', 'Medio', 'Usa llaves, desactiva contraseñas débiles y limita quién puede conectarse.'),
  port(80, 'http', 'nginx', '1.24.0', 'open', 'HTTP', 'Servidor web sin cifrado TLS.', 'Medio', 'Redirige a HTTPS y evita enviar credenciales por HTTP.'),
  port(443, 'https', 'nginx', '1.24.0', 'open', 'HTTPS', 'Servidor web con conexión cifrada TLS.', 'Bajo', 'Mantén TLS y el software del servidor actualizados.'),
  port(3389, 'ms-wbt-server', '', '', 'filtered', 'ms-wbt-server', 'Nmap marcó este puerto como filtered.', 'Informativo', 'Este estado no confirma un servicio abierto.'),
];
const host = (address, hostname, mac, vendor, extra = {}) => ({
  address, addresses: [], mac, mac_vendor: vendor, hostnames: hostname ? [hostname] : [], hostname, status: 'up', uptime_seconds: null,
  distance_hops: 1, ports: [], other_ports: [], os_matches: [], scripts: [], trace: [], ...extra,
});
const osMatch = (name, accuracy, vendor, family, type) => [{ name, accuracy, classes: [{ type, vendor, family, generation: '', accuracy, cpe: [] }] }];
const networkHosts = [
  host('192.168.1.1', 'router.lan', 'A4:2B:B0:11:22:33', 'TP-Link Technologies', { os_matches: osMatch('OpenWrt 21.02 (Linux 5.4)', 96, 'Linux', 'Linux', 'router') }),
  host('192.168.1.20', 'ESTUDIO-PC', '', ''),
  host('192.168.1.23', 'nas-casa', '00:11:32:AA:BB:CC', 'Synology Incorporated', { os_matches: osMatch('Linux 4.4', 93, 'Linux', 'Linux', 'general purpose'), ports: demoPorts }),
  host('192.168.1.31', 'iPhone-de-Ana', '6E:1A:22:9C:01:10', 'Apple'),
  host('192.168.1.34', '', 'D8:CE:3A:10:20:30', 'Xiaomi Communications'),
  host('192.168.1.40', 'LAPTOP-VENTAS', 'B4:69:21:7A:7B:7C', 'Intel Corporate', { os_matches: osMatch('Microsoft Windows 11 23H2', 95, 'Microsoft', 'Windows', 'general purpose') }),
  host('192.168.1.52', 'impresora-oficina', '00:1B:A9:55:66:77', 'Brother Industries'),
  host('192.168.1.60', 'ubuntu-srv', '08:00:27:12:34:56', 'PCS Systemtechnik', { os_matches: osMatch('Ubuntu Linux 22.04', 94, 'Linux', 'Linux', 'general purpose') }),
  host('192.168.1.77', 'Galaxy-S23', '2A:7F:10:33:44:55', ''),
  host('192.168.1.90', '', '04:5D:4B:10:20:30', 'Sony Corporation'),
];
const summary = { hosts: 1, open_ports: 5, high_risk: 2, nse_findings: 0, filtered_ports: 994, closed_ports: 0, status: 'Revisar' };
const stamp = minutesAgo => new Date(Date.now() - minutesAgo * 60000).toISOString();
const reports = [
  { name: 'demo-3.json', target: '192.168.1.23', date: stamp(4), summary, open_ports: ['22/tcp', '23/tcp', '80/tcp', '443/tcp', '445/tcp'] },
  { name: 'demo-2.json', target: '192.168.1.23', date: stamp(1500), summary: { ...summary, open_ports: 3, high_risk: 1 }, open_ports: ['22/tcp', '80/tcp', '445/tcp'] },
  { name: 'demo-1.json', target: '192.168.1.0/24', date: stamp(2900), summary: { hosts: 9, open_ports: 0, high_risk: 0 }, open_ports: [] },
];
const logs = [
  { time: stamp(4), type: 'scan-complete', target: '192.168.1.23', elapsed_ms: 41200, message: 'Escaneo terminado: 5 puertos abiertos' },
  { time: stamp(5), type: 'scan-start', target: '192.168.1.23', message: 'Escaneo iniciado' },
  { time: stamp(90), type: 'scan-cancel', target: '192.168.1.40', message: 'Escaneo cancelado por el usuario' },
  { time: stamp(1500), type: 'scan-error', target: '10.0.0.5', message: 'Nmap no pudo completar el escaneo: el equipo no respondió.' },
  { time: stamp(2900), type: 'scan-complete', target: '192.168.1.0/24', elapsed_ms: 6100, message: 'Descubrimiento terminado: 9 equipos respondieron' },
];
const scanResult = (target, options) => {
  const discovery = options.scan_type === 'ping';
  const hosts = discovery ? networkHosts.map(item => ({ ...item, ports: [], os_matches: [] })) : [{ ...(networkHosts.find(item => item.address === target) || host(target, '', '', '')), ports: demoPorts, os_matches: osMatch('Linux 4.4', 93, 'Linux', 'Linux', 'general purpose') }];
  return {
    target, hosts, runstats: { up: hosts.length, down: 0, total: hosts.length }, nmap_version: '7.99', scan_type: options.scan_type,
    nmap_command: discovery ? `-n -sn -T3 -- ${target}` : `-n -sT --top-ports 1000 -sV --version-intensity 5 -T3 -- ${target}`,
    elapsed_seconds: 41.2, summary: discovery ? { hosts: hosts.length, open_ports: 0, high_risk: 0, filtered_ports: 0, closed_ports: 0 } : summary,
    created_at: new Date().toISOString(), options, report_file: 'demo-3.json', raw_xml_file: 'demo-3.xml',
  };
};

window.trabamap = {
  system: async () => ({
    hostname: 'ESTUDIO-PC', local_ip: '192.168.1.20', nmap: '7.99', nmap_path: 'C:\\Program Files (x86)\\Nmap\\nmap.exe', gateway: '192.168.1.1', network_cidr: '192.168.1.0/24',
    interfaces: [{ name: 'Wi-Fi', address: '192.168.1.20', netmask: '255.255.255.0', cidr: '192.168.1.20/24', network: '192.168.1.0/24' }, { name: 'Ethernet', address: '10.0.0.14', netmask: '255.255.255.0', cidr: '10.0.0.14/24', network: '10.0.0.0/24' }],
    adb_inventory: { available: false, status: 'missing', devices: [], message: 'No se encontró Android Platform Tools (adb). Android solo se consulta si el teléfono ya está autorizado.' },
    local_inventory: {
      platform: 'win32', os_name: 'Windows 11 Pro', os_version: '10.0.26200', os_build: '26200', architecture: '64 bits', user_name: 'ESTUDIO-PC\\Demo Usuario', computer_name: 'ESTUDIO-PC',
      computer_manufacturer: 'Equipo', computer_model: 'de demostración', ram_total_bytes: 34359738368, ram_free_bytes: 18253611008,
      cpu: [{ name: 'Procesador de ejemplo 8 núcleos', cores: 8, logical_processors: 16 }], memory_modules: [], motherboard: [], gpu: [{ name: 'Gráfica de ejemplo' }],
      storage: [{ model: 'SSD NVMe', size_bytes: 1000204886016 }], local_addresses: [{ name: 'Wi-Fi', address: '192.168.1.20' }],
      tcp_listeners: [{ port: 135, protocol: 'TCP', address: '0.0.0.0', pid: 1124, application: 'svchost' }, { port: 445, protocol: 'TCP', address: '0.0.0.0', pid: 4, application: 'System' }, { port: 5173, protocol: 'TCP', address: '127.0.0.1', pid: 9920, application: 'node' }],
      source: 'Datos de demostración',
    },
  }),
  reports: async () => reports,
  logs: async () => logs,
  report: async name => ({ ...scanResult('192.168.1.23', { scan_type: 'connect', profile: 'quick' }), created_at: reports.find(item => item.name === name)?.date || stamp(4), report_file: name }),
  openReport: async () => true,
  exportExcel: async () => ({ name: 'Trabamap_Informe_demo.xlsx', path: '', openError: '' }),
  identify: async () => ({ sources: { mdns: 3, upnp: 1, ttl: 6 }, devices: {
    '192.168.1.31': { ttl: 64, mdns: { hostnames: ['iPhone-de-Ana'], services: ['_apple-mobdev2._tcp', '_companion-link._tcp'], instances: [], txt: {} }, upnp: null },
    '192.168.1.52': { ttl: 255, mdns: { hostnames: ['BRW001BA9556677'], services: ['_ipp._tcp', '_printer._tcp'], instances: ['Brother HL-L2350DW'], txt: { '_ipp._tcp': { ty: 'Brother HL-L2350DW series', usb_mfg: 'Brother' } } }, upnp: null },
    '192.168.1.90': { ttl: null, mdns: { hostnames: [], services: ['_googlecast._tcp'], instances: [], txt: { '_googlecast._tcp': { md: 'BRAVIA 4K VH2', fn: 'TV de la sala', rs: 'YouTube' } } }, upnp: { servers: ['Linux/5.15-android12, UPnP/1.0, Chromecast/1.6'], descriptions: [{ friendly_name: 'TV de la sala', manufacturer: 'Sony', model_name: 'BRAVIA 4K VH2', device_type: 'urn:dial-multiscreen-org:device:dial:1' }] } },
    '192.168.1.40': { ttl: 128, mdns: null, upnp: null }, '192.168.1.34': { ttl: 64, mdns: null, upnp: null }, '192.168.1.77': { ttl: 64, mdns: null, upnp: null },
  } }),
  onScanProgress: callback => { listeners.add(callback); return () => listeners.delete(callback); },
  cancelScan: async () => { cancelled = true; return true; },
  scan: async ({ target, options }) => {
    cancelled = false;
    for (const percent of [8, 27, 49, 73, 92]) {
      await wait(450);
      if (cancelled) throw new Error('Escaneo cancelado.');
      listeners.forEach(callback => callback({ message: `Connect Scan Timing: About ${percent}% done`, percent }));
    }
    return scanResult(target, options);
  },
};
