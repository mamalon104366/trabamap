import React, { useMemo, useState } from 'react';
import { Icon } from './icons.jsx';
import { explainCommand, needsAdmin } from './knowledge.js';

// Catálogo de Nmap: cada tarjeta es un escaneo completo que se lanza con un clic, sin escribir opciones.
// No incluye fuerza bruta de contraseñas, denegación de servicio, explotación ni técnicas para evadir la detección.
export const CATALOG_BASE = {
  scan_type: 'connect', ports: 'common', custom_ports: '', skip_discovery: false, service_detection: false, version_intensity: 5,
  os_detection: false, os_guess: false, os_scan_limit: false, scripts: 'off', traceroute: false, timing: 4, aggressive: false, ipv6: false,
  dns_mode: 'off', custom_args: '', idle_zombie: '', sequential_ports: false,
};
const ports = list => ({ ports: 'custom', custom_ports: list });
const script = (names, extra = '') => ({ custom_args: `--script ${names}${extra ? ` ${extra}` : ''}` });

export const CATEGORIES = [
  { id: 'descubrir', title: 'Descubrir equipos', icon: 'wifi', hint: 'Qué está encendido en la red' },
  { id: 'puertos', title: 'Puertos', icon: 'network', hint: 'Qué puertas tiene abiertas' },
  { id: 'servicios', title: 'Servicios y sistema', icon: 'cpu', hint: 'Qué programas y qué sistema operativo' },
  { id: 'web', title: 'Web y cifrado', icon: 'globe', hint: 'Páginas, certificados y TLS' },
  { id: 'windows', title: 'Windows y archivos', icon: 'server', hint: 'SMB, NetBIOS y Escritorio remoto' },
  { id: 'seguridad', title: 'Revisión de seguridad', icon: 'shield-alert', hint: 'Fallos conocidos y malas configuraciones' },
  { id: 'red', title: 'Red e infraestructura', icon: 'router', hint: 'Router, DNS, DHCP, UPnP, ruta' },
  { id: 'tecnicas', title: 'Técnicas de escaneo', icon: 'sliders', hint: 'Todos los tipos de sondeo de Nmap' },
];

export const PRESETS = [
  // ── Descubrir equipos
  { id: 'disc-ping', cat: 'descubrir', title: 'Equipos encendidos', what: 'Lista los equipos que responden en la red, sin tocar puertos.', time: 'segundos', range: true, opts: { scan_type: 'ping', dns_mode: 'resolve' } },
  { id: 'disc-list', cat: 'descubrir', title: 'Listar direcciones del rango', what: 'No envía nada: solo enumera las direcciones que entrarían en el escaneo y sus nombres DNS.', time: 'segundos', range: true, opts: { scan_type: 'list', dns_mode: 'resolve' } },
  { id: 'disc-tcp', cat: 'descubrir', title: 'Descubrir con TCP', what: 'Busca equipos tocando los puertos 22, 80, 443 y 445. Encuentra los que ignoran el ping.', time: '< 1 min', range: true, opts: { scan_type: 'ping', custom_args: '-PS22,80,443,445 -PA80,443' } },
  { id: 'disc-icmp', cat: 'descubrir', title: 'Descubrir con ICMP completo', what: 'Usa eco, marca de tiempo y máscara de red (los tres tipos de ping ICMP).', time: 'segundos', range: true, opts: { scan_type: 'ping', custom_args: '-PE -PP -PM' } },
  { id: 'disc-udp', cat: 'descubrir', title: 'Descubrir con UDP', what: 'Envía sondas UDP; útil cuando un firewall bloquea TCP e ICMP.', time: '< 1 min', range: true, opts: { scan_type: 'ping', custom_args: '-PU53,161,137' } },
  { id: 'disc-arp', cat: 'descubrir', title: 'Descubrir por ARP', what: 'El método más fiable en la red local: ningún equipo puede ocultarse del ARP.', time: 'segundos', range: true, opts: { scan_type: 'ping', custom_args: '-PR' } },
  { id: 'disc-trace', cat: 'descubrir', title: 'Equipos y ruta hasta ellos', what: 'Descubre equipos y dibuja los saltos de red para llegar a cada uno.', time: '< 1 min', range: true, opts: { scan_type: 'ping', custom_args: '--traceroute' } },

  // ── Puertos
  { id: 'port-fast', cat: 'puertos', title: 'Vistazo rápido', what: 'Los 100 puertos más usados. Para saber en segundos si hay algo abierto.', time: 'segundos', opts: { ports: 'fast' } },
  { id: 'port-1000', cat: 'puertos', title: '1.000 puertos comunes', what: 'El escaneo estándar de Nmap.', time: '< 1 min', opts: {} },
  { id: 'port-all', cat: 'puertos', title: 'Todos los puertos TCP', what: 'Los 65.535 puertos, para no dejar nada escondido.', time: '5–20 min', opts: { ports: 'all' } },
  { id: 'port-udp', cat: 'puertos', title: 'Puertos UDP comunes', what: 'Los 100 puertos UDP más usados: DNS, DHCP, SNMP, NTP…', time: '2–10 min', opts: { scan_type: 'udp', ports: 'top100' } },
  { id: 'port-both', cat: 'puertos', title: 'TCP y UDP a la vez', what: 'Los 100 puertos más usados de cada protocolo.', time: '3–10 min', opts: { scan_type: 'both', ports: 'top100' } },
  { id: 'port-web', cat: 'puertos', title: 'Solo puertos web', what: 'HTTP, HTTPS y los puertos alternativos de paneles y aplicaciones.', time: 'segundos', opts: { ...ports('80,81,443,591,3000,5000,8000,8008,8080,8081,8443,8888,9000,9090,9443'), service_detection: true } },
  { id: 'port-db', cat: 'puertos', title: 'Solo bases de datos', what: 'MySQL, PostgreSQL, SQL Server, Oracle, MongoDB, Redis, Elasticsearch…', time: 'segundos', opts: { ...ports('1433,1521,3306,5432,5984,6379,9200,11211,27017'), service_detection: true } },
  { id: 'port-remote', cat: 'puertos', title: 'Solo acceso remoto', what: 'SSH, Telnet, Escritorio remoto, VNC, WinRM, TeamViewer y ADB.', time: 'segundos', opts: { ...ports('22,23,2222,3389,5555,5800,5900,5901,5938,5985,5986'), service_detection: true } },
  { id: 'port-mail', cat: 'puertos', title: 'Solo correo', what: 'SMTP, POP3 e IMAP con y sin cifrado.', time: 'segundos', opts: { ...ports('25,110,143,465,587,993,995'), service_detection: true } },
  { id: 'port-iot', cat: 'puertos', title: 'Cámaras, TV e IoT', what: 'RTSP, MQTT, Chromecast, AirPlay, Smart TV, impresoras y UPnP.', time: 'segundos', opts: { ...ports('554,1883,8883,3000,3001,7000,8001,8002,8008,8009,8060,9100,49152,62078'), service_detection: true } },

  // ── Servicios y sistema
  { id: 'svc-version', cat: 'servicios', title: 'Programas y versiones', what: 'Identifica qué programa atiende cada puerto abierto y su versión.', time: '1–3 min', opts: { service_detection: true } },
  { id: 'svc-light', cat: 'servicios', title: 'Versiones (modo ligero)', what: 'Igual, pero con pocas sondas: más rápido y menos preciso.', time: '< 1 min', opts: { service_detection: true, version_intensity: 2 } },
  { id: 'svc-all', cat: 'servicios', title: 'Versiones (modo exhaustivo)', what: 'Prueba todas las sondas en todos los puertos abiertos.', time: '3–10 min', opts: { service_detection: true, version_intensity: 9 } },
  { id: 'svc-os', cat: 'servicios', title: 'Sistema operativo', what: 'Estima si es Windows, Linux, Android, iOS, macOS… por su huella de red.', time: '< 1 min', opts: { ports: 'top100', os_detection: true, os_guess: true } },
  { id: 'svc-banner', cat: 'servicios', title: 'Leer el saludo de cada servicio', what: 'Muestra el texto de bienvenida (banner) que envía cada puerto.', time: '< 1 min', opts: script('banner') },
  { id: 'svc-full', cat: 'servicios', title: 'Ficha completa (-A)', what: 'Versiones, sistema operativo, scripts por defecto y ruta, todo junto.', time: '3–10 min', opts: { scan_type: 'syn', aggressive: true } },
  { id: 'svc-everything', cat: 'servicios', title: 'Todo de un equipo', what: 'Todos los puertos, versiones y sistema operativo. El análisis más completo.', time: '10–30 min', opts: { ports: 'all', service_detection: true, os_detection: true, os_guess: true, scripts: 'default' } },

  // ── Web y cifrado
  { id: 'web-title', cat: 'web', title: 'Títulos y cabeceras web', what: 'Lee el título de cada página y las cabeceras del servidor.', time: '< 1 min', opts: { ...ports('80,443,8000,8080,8443,8888'), service_detection: true, ...script('http-title,http-headers,http-server-header') } },
  { id: 'web-methods', cat: 'web', title: 'Métodos HTTP permitidos', what: 'Comprueba si el servidor acepta métodos arriesgados como PUT o DELETE.', time: '< 1 min', opts: { ...ports('80,443,8080,8443'), ...script('http-methods') } },
  { id: 'web-enum', cat: 'web', title: 'Carpetas y paneles conocidos', what: 'Busca rutas típicas: /admin, /phpmyadmin, copias de seguridad, etc.', time: '1–5 min', opts: { ...ports('80,443,8080,8443'), ...script('http-enum') } },
  { id: 'web-secheaders', cat: 'web', title: 'Cabeceras de seguridad', what: 'Revisa HSTS, CSP, X-Frame-Options y otras protecciones del navegador.', time: '< 1 min', opts: { ...ports('80,443,8080,8443'), ...script('http-security-headers') } },
  { id: 'tls-cert', cat: 'web', title: 'Certificado TLS', what: 'Muestra a nombre de quién está el certificado y cuándo caduca.', time: 'segundos', opts: { ...ports('443,465,993,995,8443'), ...script('ssl-cert') } },
  { id: 'tls-ciphers', cat: 'web', title: 'Calidad del cifrado TLS', what: 'Lista versiones y cifrados aceptados y les pone nota (A–F).', time: '< 1 min', opts: { ...ports('443,465,993,995,8443'), ...script('ssl-enum-ciphers') } },
  { id: 'tls-heartbleed', cat: 'web', title: 'Fallos TLS conocidos', what: 'Comprueba Heartbleed, POODLE y cifrado DH débil.', time: '< 1 min', opts: { ...ports('443,465,993,995,8443'), ...script('ssl-heartbleed,ssl-poodle,ssl-dh-params') } },

  // ── Windows y archivos
  { id: 'win-os', cat: 'windows', title: 'Nombre y versión de Windows', what: 'Pregunta por SMB el nombre del equipo, el dominio y la versión de Windows.', time: 'segundos', opts: { ...ports('139,445'), ...script('smb-os-discovery,smb2-time,nbstat') } },
  { id: 'win-smb', cat: 'windows', title: 'Versiones y seguridad de SMB', what: 'Detecta si aún acepta SMBv1 y si exige firmar los mensajes.', time: 'segundos', opts: { ...ports('139,445'), ...script('smb-protocols,smb-security-mode,smb2-security-mode') } },
  { id: 'win-shares', cat: 'windows', title: 'Carpetas compartidas', what: 'Lista las carpetas compartidas visibles sin contraseña.', time: '< 1 min', opts: { ...ports('139,445'), ...script('smb-enum-shares') } },
  { id: 'win-eternal', cat: 'windows', title: 'EternalBlue (MS17-010)', what: 'Comprueba si el equipo sigue sin el parche del fallo que usó WannaCry.', time: 'segundos', opts: { ...ports('445'), ...script('smb-vuln-ms17-010') } },
  { id: 'win-rdp', cat: 'windows', title: 'Escritorio remoto', what: 'Revisa el cifrado del RDP y si exige autenticación de red (NLA).', time: 'segundos', opts: { ...ports('3389'), ...script('rdp-enum-encryption,rdp-ntlm-info') } },
  { id: 'win-nfs', cat: 'windows', title: 'Carpetas NFS (Linux/NAS)', what: 'Lista las carpetas exportadas por NFS y quién puede montarlas.', time: 'segundos', opts: { ...ports('111,2049'), ...script('nfs-showmount,rpcinfo') } },

  // ── Revisión de seguridad
  { id: 'sec-default', cat: 'seguridad', title: 'Revisión estándar', what: 'Versiones más los scripts por defecto de Nmap: la revisión recomendada.', time: '1–5 min', opts: { service_detection: true, scripts: 'default' } },
  { id: 'sec-safe', cat: 'seguridad', title: 'Revisión segura', what: 'Solo scripts que no pueden afectar al equipo revisado.', time: '2–8 min', opts: { service_detection: true, scripts: 'safe' } },
  { id: 'sec-vuln', cat: 'seguridad', title: 'Vulnerabilidades conocidas', what: 'Ejecuta las comprobaciones de fallos conocidos (categoría vuln).', time: '5–20 min', opts: { service_detection: true, scripts: 'vuln' } },
  { id: 'sec-vulners', cat: 'seguridad', title: 'CVE por versión', what: 'Cruza la versión de cada servicio con la base de CVE (necesita Internet).', time: '2–6 min', opts: { service_detection: true, ...script('vulners') } },
  { id: 'sec-auth', cat: 'seguridad', title: 'Accesos sin contraseña', what: 'Detecta servicios que dejan entrar sin credenciales o como invitado.', time: '2–6 min', opts: { service_detection: true, ...script('auth') } },
  { id: 'sec-ftp', cat: 'seguridad', title: 'FTP anónimo', what: 'Comprueba si el FTP permite entrar sin usuario.', time: 'segundos', opts: { ...ports('21'), service_detection: true, ...script('ftp-anon,ftp-syst') } },
  { id: 'sec-ssh', cat: 'seguridad', title: 'Seguridad de SSH', what: 'Lista algoritmos, claves del servidor y métodos de acceso permitidos.', time: 'segundos', opts: { ...ports('22,2222'), service_detection: true, ...script('ssh2-enum-algos,ssh-hostkey,ssh-auth-methods') } },
  { id: 'sec-db', cat: 'seguridad', title: 'Bases de datos expuestas', what: 'Lee la información que entregan sin contraseña MySQL, MongoDB, Redis y otras.', time: '< 1 min', opts: { ...ports('1433,3306,5432,6379,9200,27017'), service_detection: true, ...script('mysql-info,mongodb-info,redis-info,ms-sql-info') } },
  { id: 'sec-malware', cat: 'seguridad', title: 'Señales de malware', what: 'Busca puertas traseras y servicios típicos de equipos infectados.', time: '2–8 min', opts: { service_detection: true, ...script('malware') } },

  // ── Red e infraestructura
  { id: 'net-trace', cat: 'red', title: 'Ruta hasta el objetivo', what: 'Muestra cada salto (router) entre tu equipo y el destino.', time: '< 1 min', opts: { ports: 'fast', traceroute: true } },
  { id: 'net-dns', cat: 'red', title: 'Servidor DNS', what: 'Comprueba si resuelve para cualquiera (recursión abierta) y su versión.', time: 'segundos', opts: { scan_type: 'both', ...ports('53'), ...script('dns-recursion,dns-nsid') } },
  { id: 'net-dhcp', cat: 'red', title: 'Servidores DHCP de la red', what: 'Pregunta quién reparte direcciones IP; detecta un DHCP no autorizado.', time: 'segundos', noTarget: true, opts: { scan_type: 'ping', ...script('broadcast-dhcp-discover') } },
  { id: 'net-upnp', cat: 'red', title: 'UPnP del router', what: 'Lee lo que el router publica por UPnP: modelo y puertos que deja abrir.', time: 'segundos', opts: { scan_type: 'udp', ...ports('1900'), ...script('upnp-info') } },
  { id: 'net-snmp', cat: 'red', title: 'SNMP', what: 'Comprueba si el equipo de red responde a SNMP y qué información entrega.', time: 'segundos', opts: { scan_type: 'udp', ...ports('161'), ...script('snmp-info,snmp-sysdescr') } },
  { id: 'net-broadcast', cat: 'red', title: 'Anuncios de la red local', what: 'Escucha lo que los equipos anuncian por difusión: DHCP, mDNS, UPnP, NetBIOS…', time: '< 1 min', noTarget: true, opts: { scan_type: 'ping', ...script('broadcast-dns-service-discovery,broadcast-upnp-info,broadcast-netbios-master-browser,broadcast-dhcp-discover') } },
  { id: 'net-ntp', cat: 'red', title: 'Servidor de hora (NTP)', what: 'Lee la versión y la hora del servidor NTP.', time: 'segundos', opts: { scan_type: 'udp', ...ports('123'), ...script('ntp-info') } },
  { id: 'net-ipv6', cat: 'red', title: 'Escaneo IPv6', what: 'Los 1.000 puertos comunes sobre una dirección IPv6.', time: '< 1 min', opts: { ipv6: true } },

  // ── Técnicas de escaneo
  { id: 'tech-connect', cat: 'tecnicas', title: 'TCP Connect (-sT)', what: 'Conexión completa a cada puerto. Funciona sin permisos especiales.', time: '< 1 min', opts: {} },
  { id: 'tech-syn', cat: 'tecnicas', title: 'TCP SYN (-sS)', what: 'Medio saludo TCP: el clásico de Nmap, rápido y sin completar conexiones.', time: '< 1 min', opts: { scan_type: 'syn' } },
  { id: 'tech-udp', cat: 'tecnicas', title: 'UDP (-sU)', what: 'Sondea los 1.000 puertos UDP comunes. Muy lento: los equipos limitan cuántas respuestas UDP dan por segundo.', time: '15–30 min', opts: { scan_type: 'udp' } },
  { id: 'tech-ack', cat: 'tecnicas', title: 'TCP ACK (-sA)', what: 'No busca puertos abiertos: revela qué puertos filtra un firewall.', time: '< 1 min', opts: { scan_type: 'ack' } },
  { id: 'tech-window', cat: 'tecnicas', title: 'TCP Window (-sW)', what: 'Variante de ACK que en algunos sistemas distingue abierto de cerrado.', time: '< 1 min', opts: { scan_type: 'window' } },
  { id: 'tech-fin', cat: 'tecnicas', title: 'TCP FIN (-sF)', what: 'Envía solo un paquete de cierre.', time: '< 1 min', opts: { scan_type: 'fin' } },
  { id: 'tech-null', cat: 'tecnicas', title: 'TCP Null (-sN)', what: 'Paquete sin ninguna bandera TCP.', time: '< 1 min', opts: { scan_type: 'null' } },
  { id: 'tech-xmas', cat: 'tecnicas', title: 'TCP Xmas (-sX)', what: 'Paquete con FIN, PSH y URG encendidos.', time: '< 1 min', opts: { scan_type: 'xmas' } },
  { id: 'tech-maimon', cat: 'tecnicas', title: 'TCP Maimon (-sM)', what: 'Sonda FIN/ACK que delata puertos abiertos en algunos BSD.', time: '< 1 min', opts: { scan_type: 'maimon' } },
  { id: 'tech-sctp', cat: 'tecnicas', title: 'SCTP INIT (-sY)', what: 'Equivalente al SYN para el protocolo SCTP (telefonía).', time: '< 1 min', opts: { scan_type: 'sctp' } },
  { id: 'tech-proto', cat: 'tecnicas', title: 'Protocolos IP (-sO)', what: 'Averigua qué protocolos IP acepta el equipo: TCP, UDP, ICMP, GRE…', time: '2–5 min', opts: { scan_type: 'ip_proto' } },
  { id: 'tech-nopin', cat: 'tecnicas', title: 'Sin ping previo (-Pn)', what: 'Escanea aunque el equipo no responda al descubrimiento.', time: '1–3 min', opts: { skip_discovery: true } },
];

export const presetOptions = (preset, timing) => ({ ...CATALOG_BASE, ...preset.opts, timing: timing ?? CATALOG_BASE.timing, profile: preset.id });
const presetNeedsAdmin = options => needsAdmin(options) || /(^|\s)-P[EPMUR]/.test(options.custom_args || '') || options.traceroute;
export const presetFlags = options => explainCommand(options, '').slice(1, -1).map(part => part.flag).join(' ');

const SPEEDS = [[2, 'Suave'], [3, 'Normal'], [4, 'Rápido'], [5, 'Máximo']];

export function TargetPicker({ target, setTarget, system, devices }) {
  const choices = [
    system?.local_ip && { label: 'Este equipo', value: system.local_ip, icon: 'server' },
    system?.network_cidr && { label: 'Toda mi red', value: system.network_cidr, icon: 'wifi' },
    system?.gateway && { label: 'Mi router', value: system.gateway, icon: 'router' },
  ].filter(Boolean);
  return <div className="target-picker">
    <div className="target-chips">{choices.map(choice => <button type="button" key={choice.label} className={target === choice.value ? 'is-active' : ''} onClick={() => setTarget(choice.value)} title={choice.value}><Icon name={choice.icon} size={14}/>{choice.label}<code>{choice.value}</code></button>)}</div>
    {devices.length > 0 && <label className="target-device-select"><Icon name="list" size={14}/><select value={devices.some(device => device.address === target) ? target : ''} onChange={event => event.target.value && setTarget(event.target.value)} aria-label="Elegir un dispositivo encontrado">
      <option value="">Elegir un dispositivo encontrado ({devices.length})…</option>
      {devices.map(device => <option key={device.address} value={device.address}>{device.label}</option>)}
    </select></label>}
  </div>;
}

/** Sin Nmap instalado solo funcionan el descubrimiento básico y los puertos TCP. */
const worksWithoutNmap = options => ['connect', 'syn', 'ping', 'list'].includes(options.scan_type) && !options.custom_args && options.scripts === 'off' && !options.os_detection && !options.aggressive && !options.traceroute && !options.ipv6;

export function CatalogView({ target, setTarget, system, devices, busy, isReady, runPreset, openGuide }) {
  const builtin = system?.engine === 'integrado';
  const speeds = SPEEDS.filter(([value]) => value < 5 || system?.security?.allowInsaneTiming);
  const [category, setCategory] = useState('all');
  const [query, setQuery] = useState('');
  const [speed, setSpeed] = useState(4);
  const needle = query.trim().toLowerCase();
  const visible = useMemo(() => PRESETS.filter(preset => (category === 'all' || preset.cat === category) && (!needle || `${preset.title} ${preset.what} ${presetFlags(presetOptions(preset))}`.toLowerCase().includes(needle))), [category, needle]);
  const hasTarget = Boolean(target.trim());
  return <main className="page catalog-page">
    <header className="page-head"><div><span className="panel-kicker">NMAP SIN ESCRIBIR</span><h1>Catálogo de escaneos</h1><p>{PRESETS.length} escaneos de Nmap listos. Elige a quién revisar, pulsa una tarjeta y TrabaMap arma y ejecuta el comando por ti.</p></div>
      <div className="page-actions"><button className="btn-ghost" onClick={() => openGuide('tipos')}><Icon name="book" size={15}/><span>¿Qué significa cada cosa?</span></button></div></header>

    <section className="panel catalog-target">
      <div className="catalog-step"><span>1</span><div><b>¿A quién revisamos?</b><small>Elige de la lista o escribe una IP, nombre o rango.</small></div></div>
      <TargetPicker target={target} setTarget={setTarget} system={system} devices={devices}/>
      <div className="catalog-target-row">
        <label className="target-field"><Icon name="globe" size={18}/><input value={target} onChange={event => setTarget(event.target.value)} placeholder="Objetivo" aria-label="Objetivo del escaneo"/></label>
        <div className="speed-picker" role="group" aria-label="Velocidad del escaneo"><span>Velocidad</span>{speeds.map(([value, label]) => <button key={value} type="button" className={speed === value ? 'is-active' : ''} onClick={() => setSpeed(value)} title={`-T${value}`}>{label}</button>)}</div>
      </div>
    </section>

    <div className="catalog-step catalog-step-free"><span>2</span><div><b>¿Qué quieres averiguar?</b><small>Un clic en “Ejecutar” lanza el escaneo.</small></div>
      <label className="table-search"><Icon name="search" size={14}/><input value={query} onChange={event => setQuery(event.target.value)} placeholder="Buscar: heartbleed, SMB, UDP, certificado…"/></label></div>
    <nav className="pill-tabs catalog-tabs" aria-label="Categorías">
      <button className={category === 'all' ? 'is-active' : ''} onClick={() => setCategory('all')}>Todo<span>{PRESETS.length}</span></button>
      {CATEGORIES.map(item => <button key={item.id} className={category === item.id ? 'is-active' : ''} onClick={() => setCategory(item.id)} title={item.hint}><Icon name={item.icon} size={14}/>{item.title}<span>{PRESETS.filter(preset => preset.cat === item.id).length}</span></button>)}
    </nav>

    {!isReady && <div className="inline-error"><Icon name="alert" size={15}/><span>El motor local no está disponible; pulsa actualizar o reinstala TrabaMap.</span></div>}
    {builtin && <div className="inline-note"><Icon name="info" size={14}/> Nmap no está instalado: funcionan el descubrimiento de equipos y los escaneos de puertos TCP con el motor integrado. Las demás tarjetas se activan al instalar Nmap desde nmap.org.</div>}
    <div className="catalog-grid">{visible.map(preset => {
      const options = presetOptions(preset, speed);
      const admin = presetNeedsAdmin(options);
      const group = CATEGORIES.find(item => item.id === preset.cat);
      const needsNmap = builtin && !worksWithoutNmap(options);
      const blocked = busy || !isReady || needsNmap || (!hasTarget && !preset.noTarget);
      return <article className={`catalog-card ${needsNmap ? 'is-unavailable' : ''}`} key={preset.id}>
        <header><span className="tile-icon"><Icon name={group.icon} size={17}/></span><div><b>{preset.title}</b><small>{group.title} · {preset.time}</small></div></header>
        <p>{preset.what}</p>
        <code title="Comando que se ejecutará">nmap {presetFlags(options)}</code>
        <footer>
          <span className="catalog-tags">{needsNmap ? <span className="tag tag-warn" title="Instala Nmap desde nmap.org para usar este escaneo">Requiere Nmap</span> : admin ? <span className="tag tag-warn" title="Si no hay permisos, TrabaMap lo intenta con TCP Connect cuando existe equivalente">Npcap / admin</span> : <span className="tag tag-ok">Sin permisos</span>}{preset.range && <span className="tag tag-info">Ideal para toda la red</span>}{preset.noTarget && <span className="tag tag-info">No necesita objetivo</span>}</span>
          <button className="btn-primary" disabled={blocked} onClick={() => runPreset(preset, options)} title={blocked && !busy && isReady ? 'Elige primero un objetivo' : `Ejecutar sobre ${preset.noTarget ? 'la red local' : target}`}><Icon name="play" size={13}/><span>Ejecutar</span></button>
        </footer>
      </article>;
    })}</div>
    {visible.length === 0 && <div className="history-blank"><div><Icon name="search" size={22}/></div><b>Ningún escaneo coincide</b><span>Prueba otra palabra o cambia de categoría.</span></div>}
    <p className="network-footnote"><Icon name="shield-check" size={15}/> El catálogo cubre descubrimiento, puertos, versiones, sistema operativo, scripts NSE y todas las técnicas de sondeo. Deja fuera a propósito la fuerza bruta de contraseñas, la denegación de servicio, la explotación y las opciones para evadir la detección. Úsalo solo en equipos propios o autorizados.</p>
  </main>;
}
