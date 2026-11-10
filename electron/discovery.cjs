// Identificación pasiva de dispositivos de la red local.
// Solo usa lo que cada equipo anuncia voluntariamente: mDNS/Bonjour, UPnP/SSDP y la respuesta a un ping.
// No inicia sesión en ningún dispositivo ni envía nada fuera de la red local.
const dgram = require('node:dgram');
const http = require('node:http');
const { execFile } = require('node:child_process');

const MDNS_ADDRESS = '224.0.0.251';
const SSDP_ADDRESS = '239.255.255.250';
const MDNS_SERVICES = [
  '_services._dns-sd._udp', '_device-info._tcp', '_airplay._tcp', '_raop._tcp', '_companion-link._tcp', '_apple-mobdev2._tcp',
  '_googlecast._tcp', '_androidtvremote2._tcp', '_amzn-wplay._tcp', '_spotify-connect._tcp', '_sonos._tcp', '_hap._tcp', '_matter._tcp',
  '_ipp._tcp', '_ipps._tcp', '_printer._tcp', '_pdl-datastream._tcp', '_uscan._tcp', '_scanner._tcp',
  '_smb._tcp', '_afpovertcp._tcp', '_ssh._tcp', '_sftp-ssh._tcp', '_rfb._tcp', '_workstation._tcp', '_http._tcp',
  '_adb-tls-connect._tcp', '_nvstream._tcp', '_rdlink._tcp', '_homekit._tcp', '_remotepairing._tcp', '_sleep-proxy._udp', '_touch-able._tcp',
];
const isPrivate = address => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.)/.test(String(address || ''));

function encodeName(name) {
  const parts = name.split('.').filter(Boolean).map(label => { const bytes = Buffer.from(label, 'utf8'); return Buffer.concat([Buffer.from([bytes.length]), bytes]); });
  return Buffer.concat([...parts, Buffer.from([0])]);
}
function buildQuery(names, suffix = '.local') {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(names.length, 4);
  // Tipo PTR (12), clase IN con el bit de "respuesta unicast" para recibir la contestación en nuestro puerto.
  return Buffer.concat([header, ...names.map(name => Buffer.concat([encodeName(`${name}${suffix}`), Buffer.from([0, 12, 0x80, 1])]))]);
}
/** Pregunta "¿cómo te llamas?" a una IP concreta: 9.1.168.192.in-addr.arpa → iPhone-de-Ana.local */
const reverseQuery = address => buildQuery([`${address.split('.').reverse().join('.')}.in-addr.arpa`], '');
function readName(buffer, start) {
  const labels = [];
  let offset = start, end = -1, jumps = 0;
  while (offset < buffer.length) {
    const length = buffer[offset];
    if (length === 0) { offset += 1; break; }
    if ((length & 0xc0) === 0xc0) {
      if (offset + 1 >= buffer.length || ++jumps > 20) throw new Error('nombre DNS inválido');
      if (end < 0) end = offset + 2;
      offset = ((length & 0x3f) << 8) | buffer[offset + 1];
      continue;
    }
    if (offset + 1 + length > buffer.length) throw new Error('nombre DNS truncado');
    labels.push(buffer.toString('utf8', offset + 1, offset + 1 + length));
    offset += 1 + length;
  }
  return { name: labels.join('.'), next: end < 0 ? offset : end };
}
function parseDnsPacket(buffer) {
  const records = [];
  if (buffer.length < 12) return records;
  const questions = buffer.readUInt16BE(4);
  const total = buffer.readUInt16BE(6) + buffer.readUInt16BE(8) + buffer.readUInt16BE(10);
  let offset = 12;
  try {
    for (let index = 0; index < questions; index++) offset = readName(buffer, offset).next + 4;
    for (let index = 0; index < total && offset < buffer.length; index++) {
      const owner = readName(buffer, offset);
      offset = owner.next;
      if (offset + 10 > buffer.length) break;
      const type = buffer.readUInt16BE(offset);
      const length = buffer.readUInt16BE(offset + 8);
      const data = offset + 10;
      if (data + length > buffer.length) break;
      if (type === 12) records.push({ type: 'PTR', name: owner.name, value: readName(buffer, data).name });
      else if (type === 33 && length >= 7) records.push({ type: 'SRV', name: owner.name, port: buffer.readUInt16BE(data + 4), value: readName(buffer, data + 6).name });
      else if (type === 1 && length === 4) records.push({ type: 'A', name: owner.name, value: [...buffer.subarray(data, data + 4)].join('.') });
      else if (type === 16) {
        const entries = {};
        for (let cursor = data; cursor < data + length;) {
          const size = buffer[cursor];
          const text = buffer.toString('utf8', cursor + 1, Math.min(cursor + 1 + size, data + length));
          const split = text.indexOf('=');
          if (split > 0) entries[text.slice(0, split).toLowerCase()] = text.slice(split + 1).slice(0, 200);
          cursor += 1 + size;
        }
        records.push({ type: 'TXT', name: owner.name, value: entries });
      }
      offset = data + length;
    }
  } catch { /* Paquete mal formado: se conserva lo leído hasta aquí. */ }
  return records;
}

function emptyMdns() { return { hostnames: [], services: [], instances: [], txt: {} }; }
function addUnique(list, value, limit = 24) { if (value && !list.includes(value) && list.length < limit) list.push(value); }
function absorbMdns(devices, address, records) {
  const device = devices.get(address) || emptyMdns();
  for (const record of records) {
    const service = record.name.match(/(_[a-z0-9-]+\._(?:tcp|udp))\.local$/i)?.[1]?.toLowerCase();
    if (record.type === 'PTR' && /\.in-addr\.arpa$/i.test(record.name)) { addUnique(device.hostnames, record.value.replace(/\.local$/i, '')); device.answers_name = true; }
    else if (record.type === 'PTR') {
      if (record.name.startsWith('_services._dns-sd')) addUnique(device.services, record.value.replace(/\.local$/i, '').toLowerCase());
      else if (service) { addUnique(device.services, service); addUnique(device.instances, record.value.replace(new RegExp(`\\.${service.replace(/\./g, '\\.')}\\.local$`, 'i'), '')); }
    } else if (record.type === 'SRV') { if (service) addUnique(device.services, service); addUnique(device.hostnames, record.value.replace(/\.local$/i, '')); }
    else if (record.type === 'A' && record.value === address) addUnique(device.hostnames, record.name.replace(/\.local$/i, ''));
    else if (record.type === 'TXT' && service) {
      addUnique(device.services, service);
      // Cada servicio guarda sus propias claves: "model" significa cosas distintas en AirPlay y en una impresora.
      device.txt[service] = { ...(device.txt[service] || {}), ...Object.fromEntries(Object.entries(record.value).slice(0, 30)) };
    }
  }
  devices.set(address, device);
}

function mdnsScan(localAddress, addresses = [], duration = 3400) {
  return new Promise(resolve => {
    const devices = new Map();
    const socket = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    let finished = false;
    const finish = () => { if (finished) return; finished = true; try { socket.close(); } catch { /* ya cerrado */ } resolve(devices); };
    socket.on('error', finish);
    socket.on('message', (message, remote) => { if (isPrivate(remote.address)) absorbMdns(devices, remote.address, parseDnsPacket(message)); });
    socket.bind(0, localAddress, () => {
      try { socket.setMulticastInterface(localAddress); socket.setMulticastTTL(1); } catch { /* interfaz sin multidifusión */ }
      const send = () => {
        for (let index = 0; index < MDNS_SERVICES.length; index += 8) {
          const packet = buildQuery(MDNS_SERVICES.slice(index, index + 8));
          socket.send(packet, 5353, MDNS_ADDRESS, () => {});
        }
        // Consulta directa a cada equipo: los Apple, Windows y Linux con Bonjour/Avahi responden con su nombre.
        for (const address of addresses) if (address !== localAddress) {
          socket.send(reverseQuery(address), 5353, address, () => {});
          // Y la lista de servicios, preguntada directamente: los equipos Apple siempre contestan.
          socket.send(buildQuery(['_services._dns-sd._udp', '_companion-link._tcp', '_rdlink._tcp', '_apple-mobdev2._tcp', '_remotepairing._tcp']), 5353, address, () => {});
        }
      };
      send();
      setTimeout(() => { if (!finished) send(); }, 900);
      setTimeout(finish, duration);
    });
  });
}

function fetchText(url, timeout = 2500, limit = 200000) {
  return new Promise(resolve => {
    let done = false;
    const end = value => { if (!done) { done = true; resolve(value); } };
    try {
      const request = http.get(url, { timeout, headers: { 'User-Agent': 'TrabaMap UPnP/1.1' } }, response => {
        if (response.statusCode !== 200) { response.resume(); end(''); return; }
        let body = '';
        response.setEncoding('utf8');
        response.on('data', chunk => { body += chunk; if (body.length > limit) { request.destroy(); end(body); } });
        response.on('end', () => end(body));
      });
      request.on('timeout', () => { request.destroy(); end(''); });
      request.on('error', () => end(''));
    } catch { end(''); }
  });
}
const xmlValue = (xml, tag) => {
  const value = xml.match(new RegExp(`<${tag}>\\s*([^<]{1,200})\\s*</${tag}>`, 'i'))?.[1] || '';
  return value.replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/&#39;|&apos;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').trim();
};

function ssdpScan(localAddress, duration = 3200) {
  return new Promise(resolve => {
    const found = new Map();
    const socket = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    let finished = false;
    const finish = async () => {
      if (finished) return; finished = true;
      try { socket.close(); } catch { /* ya cerrado */ }
      // Solo se descarga la descripción que el propio dispositivo publica desde su misma IP local.
      await Promise.all([...found.entries()].map(async ([address, device]) => {
        for (const location of device.locations.slice(0, 3)) {
          const xml = await fetchText(location);
          if (!xml) continue;
          const block = xml.match(/<device>[\s\S]*?(?=<deviceList>|<serviceList>|<\/device>)/i)?.[0] || xml;
          const description = { friendly_name: xmlValue(block, 'friendlyName'), manufacturer: xmlValue(block, 'manufacturer'), model_name: xmlValue(block, 'modelName'), model_number: xmlValue(block, 'modelNumber'), model_description: xmlValue(block, 'modelDescription'), device_type: xmlValue(block, 'deviceType') };
          if (Object.values(description).some(Boolean)) device.descriptions.push(description);
        }
        delete device.locations;
      }));
      resolve(found);
    };
    socket.on('error', finish);
    socket.on('message', (message, remote) => {
      if (!isPrivate(remote.address)) return;
      const text = message.toString('utf8', 0, Math.min(message.length, 2000));
      const header = name => text.match(new RegExp(`^${name}:\\s*(.+)$`, 'mi'))?.[1]?.trim() || '';
      const device = found.get(remote.address) || { servers: [], targets: [], locations: [], descriptions: [] };
      addUnique(device.servers, header('SERVER').slice(0, 160));
      addUnique(device.targets, header('ST').slice(0, 120), 40);
      const location = header('LOCATION');
      try { if (location && new URL(location).hostname === remote.address && /^http:$/.test(new URL(location).protocol)) addUnique(device.locations, location, 6); } catch { /* URL inválida */ }
      found.set(remote.address, device);
    });
    socket.bind(0, localAddress, () => {
      try { socket.setMulticastInterface(localAddress); socket.setMulticastTTL(2); } catch { /* interfaz sin multidifusión */ }
      const search = target => Buffer.from(`M-SEARCH * HTTP/1.1\r\nHOST: ${SSDP_ADDRESS}:1900\r\nMAN: "ssdp:discover"\r\nMX: 2\r\nST: ${target}\r\n\r\n`);
      const send = () => { for (const target of ['ssdp:all', 'upnp:rootdevice', 'urn:dial-multiscreen-org:service:dial:1']) socket.send(search(target), 1900, SSDP_ADDRESS, () => {}); };
      send();
      setTimeout(() => { if (!finished) send(); }, 700);
      setTimeout(finish, duration);
    });
  });
}

function pingTtl(address) {
  return new Promise(resolve => {
    const args = process.platform === 'win32' ? ['-n', '1', '-w', '900', address] : ['-c', '1', '-W', '1', address];
    execFile(process.platform === 'win32' ? 'ping.exe' : 'ping', args, { encoding: 'utf8', windowsHide: true, timeout: 2500 }, (_error, stdout) => {
      const ttl = Number(String(stdout || '').match(/ttl[=:]\s*(\d+)/i)?.[1]);
      resolve(Number.isFinite(ttl) && ttl > 0 ? ttl : null);
    });
  });
}
async function pingAll(addresses, concurrency = 24) {
  const results = new Map();
  const queue = [...addresses];
  await Promise.all(Array.from({ length: Math.min(concurrency, queue.length) }, async () => {
    while (queue.length) { const address = queue.shift(); results.set(address, await pingTtl(address)); }
  }));
  return results;
}

/** Devuelve, por IP, lo que cada dispositivo anunció de sí mismo. */
async function identifyNetwork(localAddress, addresses) {
  const valid = [...new Set((addresses || []).filter(address => typeof address === 'string' && /^\d{1,3}(\.\d{1,3}){3}$/.test(address) && isPrivate(address)))].slice(0, 1024);
  if (!localAddress || !isPrivate(localAddress)) return { devices: {}, sources: { mdns: 0, upnp: 0, ttl: 0 } };
  const [mdns, upnp, ttl] = await Promise.all([mdnsScan(localAddress, valid).catch(() => new Map()), ssdpScan(localAddress).catch(() => new Map()), pingAll(valid).catch(() => new Map())]);
  const devices = {};
  for (const address of new Set([...valid, ...mdns.keys(), ...upnp.keys()])) {
    const entry = { mdns: mdns.get(address) || null, upnp: upnp.get(address) || null, ttl: ttl.get(address) ?? null };
    if (entry.mdns || entry.upnp || entry.ttl) devices[address] = entry;
  }
  return { devices, sources: { mdns: mdns.size, upnp: upnp.size, ttl: [...ttl.values()].filter(Boolean).length } };
}

module.exports = { identifyNetwork, parseDnsPacket, buildQuery, MDNS_SERVICES };

if (require.main === module) {
  // Prueba directa: node electron/discovery.cjs <ip-local> [ip ...]
  identifyNetwork(process.argv[2], process.argv.slice(3)).then(result => console.log(JSON.stringify(result, null, 1)));
}
