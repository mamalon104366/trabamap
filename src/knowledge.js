// Base de conocimiento de TrabaMap: todo lo que la interfaz explica en español.

export const PROFILES = [
  { id: 'quick', icon: 'zap', title: 'Rápido', flags: '-sT --top-ports 1000 -sV -T3', time: '1–3 min', admin: false,
    what: 'Revisa los 1.000 puertos TCP más usados y le pregunta a cada servicio qué programa y versión es.',
    when: 'La primera revisión de cualquier equipo. No necesita permisos de administrador.' },
  { id: 'complete', icon: 'network', title: 'Completo', flags: '-sS -p- -sV -O -T3', time: '5–30 min', admin: true,
    what: 'Recorre los 65.535 puertos TCP, identifica servicios y estima el sistema operativo.',
    when: 'Cuando quieres estar seguro de que no queda ningún servicio escondido en un puerto raro.' },
  { id: 'intense', icon: 'shield-alert', title: 'Intensivo', flags: '-sS --top-ports 1000 -A -T4', time: '3–10 min', admin: true,
    what: 'Activa el modo -A: versiones, sistema operativo, scripts NSE por defecto y traza de ruta.',
    when: 'Para una ficha lo más completa posible de un equipo propio. Hace más ruido en la red.' },
  { id: 'discovery', icon: 'wifi', title: 'Descubrir', flags: '-sn', time: 'segundos', admin: false,
    what: 'No toca puertos: solo pregunta qué equipos del rango local están encendidos y responden.',
    when: 'Para ver qué hay conectado a tu red antes de escanear un equipo concreto.' },
];

export const PORT_STATES = {
  open: { label: 'Abierto', tone: 'open', text: 'Un programa está aceptando conexiones en este puerto. Es lo que hay que revisar: confirma que debe estar ahí.' },
  closed: { label: 'Cerrado', tone: 'closed', text: 'El equipo respondió, pero ningún programa escucha en ese puerto. No hay servicio que atacar.' },
  filtered: { label: 'Filtrado', tone: 'filtered', text: 'Algo (normalmente un firewall) se tragó la sonda y Nmap no pudo saber si está abierto o cerrado.' },
  unfiltered: { label: 'Sin filtrar', tone: 'filtered', text: 'El puerto es alcanzable, pero este tipo de escaneo (ACK) no distingue si está abierto o cerrado.' },
  'open|filtered': { label: 'Abierto o filtrado', tone: 'filtered', text: 'No hubo respuesta. Típico en UDP: puede estar abierto o protegido por un firewall.' },
  'closed|filtered': { label: 'Cerrado o filtrado', tone: 'filtered', text: 'Nmap no pudo decidir entre cerrado y filtrado (solo ocurre en escaneos idle).' },
};

export const RISKS = [
  { id: 'Muy alto', tone: 'critical', text: 'Protocolo obsoleto que viaja sin cifrar (por ejemplo Telnet). Conviene apagarlo.' },
  { id: 'Alto', tone: 'high', text: 'Servicio delicado si queda expuesto: archivos compartidos, bases de datos, escritorio remoto.' },
  { id: 'Medio', tone: 'medium', text: 'Servicio normal que depende de estar bien configurado y actualizado.' },
  { id: 'Bajo', tone: 'low', text: 'Servicio cifrado y habitual. Solo hay que mantenerlo al día.' },
  { id: 'Informativo', tone: 'info', text: 'Puerto cerrado o filtrado; se muestra como dato, no como hallazgo.' },
];

export const SCAN_TYPES = {
  connect: { flag: '-sT', name: 'TCP Connect', admin: false, text: 'Abre una conexión TCP completa a cada puerto, como haría cualquier programa. Funciona sin permisos especiales.' },
  syn: { flag: '-sS', name: 'TCP SYN', admin: true, text: 'Envía solo el primer paquete del saludo TCP y no termina la conexión. Más rápido y discreto; necesita Npcap/administrador.' },
  udp: { flag: '-sU', name: 'UDP', admin: true, text: 'Sondea servicios UDP (DNS, DHCP, SNMP…). Es lento porque UDP no confirma la recepción.' },
  both: { flag: '-sS -sU', name: 'TCP SYN + UDP', admin: true, text: 'Combina los dos anteriores en una sola pasada.' },
  ack: { flag: '-sA', name: 'TCP ACK', admin: true, text: 'No busca puertos abiertos: sirve para saber qué puertos deja pasar un firewall.' },
  window: { flag: '-sW', name: 'TCP Window', admin: true, text: 'Variante de ACK que en algunos sistemas distingue abierto de cerrado por el tamaño de ventana.' },
  maimon: { flag: '-sM', name: 'TCP Maimon', admin: true, text: 'Sonda FIN/ACK; algunos sistemas BSD antiguos responden distinto si el puerto está abierto.' },
  fin: { flag: '-sF', name: 'TCP FIN', admin: true, text: 'Envía un paquete de cierre sin conexión previa. Algunos firewalls simples lo dejan pasar.' },
  null: { flag: '-sN', name: 'TCP Null', admin: true, text: 'Paquete sin ninguna bandera TCP. Mismo propósito que FIN.' },
  xmas: { flag: '-sX', name: 'TCP Xmas', admin: true, text: 'Paquete con las banderas FIN, PSH y URG encendidas, "como un árbol de Navidad".' },
  sctp: { flag: '-sY', name: 'SCTP INIT', admin: true, text: 'Equivalente al SYN para el protocolo SCTP, usado en telefonía.' },
  sctp_cookie: { flag: '-sZ', name: 'SCTP Cookie', admin: true, text: 'Sonda SCTP alternativa, más discreta que INIT.' },
  ip_proto: { flag: '-sO', name: 'Protocolos IP', admin: true, text: 'En vez de puertos, averigua qué protocolos IP (TCP, UDP, ICMP, GRE…) acepta el equipo.' },
  ping: { flag: '-sn', name: 'Descubrimiento', admin: false, text: 'Solo comprueba qué equipos responden; no escanea puertos.' },
  list: { flag: '-sL', name: 'Lista sin sondeo', admin: false, text: 'No envía nada al objetivo: solo lista las direcciones que se escanearían.' },
};

export const OPTION_HELP = [
  { flag: '-sV', name: 'Servicios y versiones', text: 'Tras encontrar un puerto abierto, conversa con él para averiguar qué programa es y su versión.' },
  { flag: '-O', name: 'Sistema operativo', text: 'Compara cómo responde el equipo con una base de huellas para estimar su sistema. Es una estimación, no una certeza.' },
  { flag: '-Pn', name: 'Omitir ping previo', text: 'Escanea aunque el equipo no responda al ping. Útil cuando un firewall bloquea el descubrimiento.' },
  { flag: '--traceroute', name: 'Trazar ruta', text: 'Muestra los saltos (routers) entre tu equipo y el objetivo.' },
  { flag: '-sC / --script', name: 'Scripts NSE', text: 'Pequeños programas de Nmap que consultan más detalles. "safe" no molesta; "vuln" busca fallos conocidos y es más intrusivo.' },
  { flag: '-T0 … -T5', name: 'Velocidad', text: 'T0 es lentísimo y sigiloso, T3 es el normal, T5 es muy agresivo y puede perder resultados.' },
  { flag: '-n / -R', name: 'Resolución DNS', text: '-n no traduce IPs a nombres (más rápido); -R lo fuerza siempre.' },
  { flag: '-A', name: 'Modo avanzado', text: 'Atajo que activa -sV, -O, scripts por defecto y traceroute a la vez.' },
  { flag: '-6', name: 'IPv6', text: 'Escanea direcciones IPv6 en lugar de IPv4.' },
  { flag: '-r', name: 'Puertos en orden', text: 'Recorre los puertos de menor a mayor en vez de aleatoriamente.' },
];

export const GLOSSARY = [
  { term: 'Dirección IP', text: 'El "número de casa" de un equipo dentro de la red, por ejemplo 192.168.1.20.' },
  { term: 'Puerto', text: 'Una "puerta" numerada (1–65535) por la que un programa atiende conexiones. La web usa el 443, SSH el 22.' },
  { term: 'Servicio', text: 'El programa que escucha detrás de un puerto abierto.' },
  { term: 'Router / puerta de enlace', text: 'El equipo que conecta tu red local con Internet. Suele ser la .1 del rango.' },
  { term: 'Rango / CIDR', text: 'Un grupo de direcciones. 192.168.1.0/24 son las 256 direcciones que empiezan por 192.168.1.' },
  { term: 'MAC', text: 'Identificador físico de la tarjeta de red. Sus primeros dígitos (OUI) delatan al fabricante, salvo en móviles con MAC aleatoria.' },
  { term: 'Hostname', text: 'El nombre con el que un equipo se anuncia en la red.' },
  { term: 'TCP y UDP', text: 'Los dos protocolos de transporte. TCP confirma cada entrega; UDP envía sin confirmar y es más difícil de escanear.' },
  { term: 'Firewall', text: 'Filtro que decide qué conexiones entran o salen. Es quien provoca los puertos "filtrados".' },
  { term: 'NSE', text: 'Nmap Scripting Engine: scripts que amplían lo que Nmap puede averiguar de un servicio.' },
  { term: 'Npcap', text: 'Controlador de Windows que Nmap necesita para los escaneos "raw" (SYN, UDP, detección de SO).' },
  { term: 'Huella (fingerprint)', text: 'Patrón de respuestas que permite adivinar el sistema operativo o el programa sin iniciar sesión en él.' },
];

export const GUIDE_SECTIONS = [
  { id: 'como-funciona', title: 'Cómo funciona' },
  { id: 'perfiles', title: 'Perfiles de escaneo' },
  { id: 'estados', title: 'Estados de un puerto' },
  { id: 'riesgo', title: 'Niveles de riesgo' },
  { id: 'tipos', title: 'Tipos de escaneo' },
  { id: 'opciones', title: 'Opciones de Nmap' },
  { id: 'glosario', title: 'Glosario' },
  { id: 'limites', title: 'Límites y uso responsable' },
];

const PORT_HELP = {
  common: ['--top-ports 1000', 'Revisa los 1.000 puertos más frecuentes.'],
  top100: ['--top-ports 100', 'Revisa solo los 100 puertos más frecuentes.'],
  fast: ['-F', 'Modo rápido: los 100 puertos más comunes.'],
  all: ['-p-', 'Revisa los 65.535 puertos. Puede tardar bastante.'],
};
const SCRIPT_HELP = {
  default: ['-sC', 'Ejecuta los scripts NSE por defecto.'],
  safe: ['--script safe', 'Scripts NSE marcados como seguros.'],
  discovery: ['--script discovery', 'Scripts que buscan más información del equipo.'],
  vuln: ['--script "vuln and not (dos or exploit or brute or fuzzer)"', 'Comprueba vulnerabilidades conocidas, excluyendo las pruebas que pueden tumbar o explotar el servicio.'],
};
const TIMING_HELP = ['Paranoico: lentísimo, para no ser detectado.', 'Sigiloso: muy lento.', 'Educado: reduce la carga en la red.', 'Normal: equilibrio por defecto.', 'Agresivo: rápido en redes fiables.', 'Insano: máxima velocidad, puede perder resultados.'];

/** Refleja en la interfaz el comando que construye core/scanner.py, con una explicación por parte. */
export function explainCommand(options, target) {
  const parts = [{ flag: 'nmap', text: 'El motor de escaneo. TrabaMap añade por dentro la salida XML y el progreso.' }];
  const add = (flag, text) => parts.push({ flag, text });
  const type = SCAN_TYPES[options.scan_type] || SCAN_TYPES.connect;
  const noPorts = ['ping', 'list', 'ip_proto'].includes(options.scan_type);
  const canServices = ['connect', 'syn', 'udp', 'both', 'sctp'].includes(options.scan_type);
  const canOs = !['ping', 'list', 'ip_proto', 'idle'].includes(options.scan_type);
  if (options.dns_mode === 'off') add('-n', 'No traduce IPs a nombres: más rápido.');
  if (options.dns_mode === 'force') add('-R', 'Fuerza la búsqueda del nombre de cada IP.');
  add(type.flag, type.text);
  if (options.ipv6) add('-6', 'Usa IPv6.');
  if (!noPorts) {
    if (options.ports === 'top') add(`--top-ports ${options.top_port_count || 1000}`, 'Revisa esa cantidad de puertos, empezando por los más frecuentes.');
    else if (options.ports === 'custom') add(`-p ${options.custom_ports || '‹puertos›'}`, 'Revisa solo los puertos o rangos que escribiste.');
    else if (PORT_HELP[options.ports]) add(...PORT_HELP[options.ports]);
  }
  if (!['ping', 'list'].includes(options.scan_type) && options.skip_discovery) add('-Pn', 'Escanea aunque el equipo no responda al ping.');
  if (options.aggressive) add('-A', 'Modo avanzado: versiones, sistema operativo, scripts por defecto y traza de ruta.');
  else {
    if (options.service_detection && canServices) {
      add('-sV', 'Identifica el programa y la versión de cada puerto abierto.');
      add(`--version-intensity ${options.version_intensity}`, 'Cuánto insiste al identificar versiones (0 ligero, 9 exhaustivo).');
    }
    if (options.os_detection && canOs) {
      add('-O', 'Estima el sistema operativo por su huella de red.');
      if (options.os_guess) add('--osscan-guess', 'Propone el sistema más parecido aunque la huella no sea exacta.');
      if (options.os_scan_limit) add('--osscan-limit', 'Solo intenta la detección cuando hay buenas condiciones.');
    }
    if (SCRIPT_HELP[options.scripts]) add(...SCRIPT_HELP[options.scripts]);
    if (options.traceroute) add('--traceroute', 'Muestra los saltos de red hasta el objetivo.');
  }
  add(`-T${options.timing}`, `Velocidad ${options.timing} de 5. ${TIMING_HELP[options.timing] || ''}`);
  if (options.sequential_ports && !noPorts) add('-r', 'Recorre los puertos en orden.');
  if ((options.custom_args || '').trim()) add(options.custom_args.trim(), 'Parámetros adicionales que escribiste; se pasan tal cual a Nmap.');
  add(target?.trim() || '‹objetivo›', 'El equipo, lista o rango de red que se va a revisar.');
  return parts;
}

export const needsAdmin = options => Boolean(SCAN_TYPES[options.scan_type]?.admin || options.os_detection || options.aggressive);
