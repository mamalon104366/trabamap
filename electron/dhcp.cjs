// Escucha pasiva de DHCP.
// Cuando un equipo se conecta a la red (o renueva su dirección) envía un mensaje DHCP por difusión que
// cualquier equipo del segmento recibe. Ese mensaje delata el sistema con mucha fiabilidad:
//   · Android se presenta como "android-dhcp-14" (incluye la versión).
//   · Windows como "MSFT 5.0".
//   · iOS y macOS piden una lista de parámetros característica y no envían clase de fabricante.
// TrabaMap solo escucha: no responde, no asigna direcciones y no interfiere con el router.
const dgram = require('node:dgram');
const fs = require('node:fs');

const seen = new Map();
let socket = null;
let status = { active: false, reason: 'No iniciada', since: null };
let storeFile = '';
let saveTimer = null;

function parseDhcp(buffer) {
  if (buffer.length < 244 || buffer[0] !== 1 || buffer[1] !== 1 || buffer[2] !== 6) return null;      // solo peticiones de clientes Ethernet
  if (buffer.readUInt32BE(236) !== 0x63825363) return null;                                           // "magic cookie" de DHCP
  const mac = [...buffer.subarray(28, 34)].map(byte => byte.toString(16).padStart(2, '0')).join(':').toUpperCase();
  const record = { mac, ip: [...buffer.subarray(12, 16)].join('.'), type: 0, hostname: '', vendor_class: '', params: [] };
  for (let offset = 240; offset < buffer.length;) {
    const code = buffer[offset];
    if (code === 255) break;
    if (code === 0) { offset += 1; continue; }
    const length = buffer[offset + 1];
    const data = buffer.subarray(offset + 2, offset + 2 + length);
    if (data.length < length) break;
    if (code === 53) record.type = data[0];
    else if (code === 12) record.hostname = data.toString('utf8').replace(/[^\x20-\x7e -￿]/g, '').slice(0, 64);
    else if (code === 60) record.vendor_class = data.toString('latin1').replace(/[^\x20-\x7e]/g, '').slice(0, 64);
    else if (code === 55) record.params = [...data].slice(0, 40);
    else if (code === 50 && length === 4) record.requested_ip = [...data].join('.');
    offset += 2 + length;
  }
  if (record.ip === '0.0.0.0') record.ip = record.requested_ip || '';
  delete record.requested_ip;
  return record.type === 1 || record.type === 3 || record.type === 8 ? record : null;                // DISCOVER, REQUEST o INFORM
}

function remember(record) {
  const previous = seen.get(record.mac) || {};
  seen.set(record.mac, { ...previous, ...record, ip: record.ip || previous.ip || '', hostname: record.hostname || previous.hostname || '', vendor_class: record.vendor_class || previous.vendor_class || '', params: record.params.length ? record.params : previous.params || [], seen_at: new Date().toISOString() });
  if (seen.size > 2000) seen.delete(seen.keys().next().value);
  if (storeFile && !saveTimer) saveTimer = setTimeout(() => {
    saveTimer = null;
    try { fs.writeFileSync(storeFile, JSON.stringify([...seen.values()]), 'utf8'); } catch { /* sin permiso de escritura: se conserva en memoria */ }
  }, 1500);
}

function startDhcpListener(file) {
  if (socket) return status;
  storeFile = file || '';
  try { for (const record of JSON.parse(fs.readFileSync(storeFile, 'utf8'))) if (record?.mac) seen.set(record.mac, record); } catch { /* primera ejecución */ }
  try {
    socket = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    socket.on('error', error => {
      status = { active: false, since: null, reason: error.code === 'EADDRINUSE' ? 'El puerto DHCP (67) ya lo usa otro programa de este equipo.' : error.code === 'EACCES' ? 'El sistema no permitió escuchar el puerto DHCP (67).' : error.message };
      try { socket.close(); } catch { /* ya cerrado */ }
      socket = null;
    });
    socket.on('message', message => { const record = parseDhcp(message); if (record) remember(record); });
    socket.bind(67, '0.0.0.0', () => { status = { active: true, reason: '', since: new Date().toISOString() }; });
  } catch (error) { status = { active: false, since: null, reason: error.message }; socket = null; }
  return status;
}

const dhcpStatus = () => ({ ...status, seen: seen.size });
/** Registro DHCP de un equipo, buscado por MAC (lo fiable) o por IP. */
function dhcpFor(address, mac) {
  const byMac = mac && seen.get(String(mac).toUpperCase());
  if (byMac) return byMac;
  return [...seen.values()].filter(record => record.ip === address).sort((a, b) => String(b.seen_at).localeCompare(String(a.seen_at)))[0] || null;
}

module.exports = { startDhcpListener, dhcpStatus, dhcpFor, parseDhcp };
