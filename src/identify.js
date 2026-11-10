// Motor de identificación de TrabaMap.
// Combina las pistas de cada equipo y devuelve qué es, de qué marca y modelo, y POR QUÉ se concluye eso.
// Cada conclusión lleva su evidencia: nada se afirma sin una pista que lo respalde.

export const CATEGORY_LABELS = {
  tv: 'Televisor / streaming', phone: 'Teléfono o tableta', computer: 'Computador', router: 'Router / equipo de red', printer: 'Impresora',
  console: 'Consola de videojuegos', camera: 'Cámara IP', speaker: 'Altavoz inteligente', iot: 'Dispositivo inteligente (IoT)', nas: 'Almacenamiento en red (NAS)', device: 'Dispositivo de red',
};
export const OS_FAMILIES = [
  { id: 'windows', label: 'Windows' }, { id: 'android', label: 'Android' }, { id: 'ios', label: 'iOS / iPadOS' }, { id: 'macos', label: 'macOS' },
  { id: 'linux', label: 'Linux' }, { id: 'mobile', label: 'Móvil (Android o iOS)' }, { id: 'apple', label: 'Apple (iOS o macOS)' }, { id: 'other', label: 'Otros sistemas' }, { id: 'unknown', label: 'Sin determinar' },
];
/** Reduce el texto del sistema a una familia para poder filtrar: windows, android, ios, macos, linux… */
export function familyOf(os) {
  const text = String(os || '').toLowerCase();
  if (/android o ios/.test(text)) return 'mobile';
  if (/ios o macos/.test(text)) return 'apple';
  if (/android|fire os|google tv/.test(text)) return 'android';
  if (/\bios\b|ipados|iphone|ipad/.test(text)) return 'ios';
  if (/windows/.test(text)) return 'windows';
  if (/macos|mac os|darwin|os x/.test(text)) return 'macos';
  if (/linux|ubuntu|debian|fedora|openwrt|raspberry|unix|bsd/.test(text)) return 'linux';
  if (/tizen|webos|roku|tvos|cast os|audioos|watchos/.test(text)) return 'other';
  return 'unknown';
}
export const CONFIDENCE_LABELS = { alta: 'Confianza alta', media: 'Confianza media', baja: 'Confianza baja' };

// Puertos "firma": pocos, pero cada uno delata un tipo de dispositivo.
export const SIGNATURE_PORTS = [22, 80, 135, 139, 443, 445, 515, 548, 554, 631, 1883, 3000, 3001, 3389, 5000, 5555, 7000, 8001, 8002, 8008, 8009, 8060, 8080, 8443, 9100, 32400, 49152, 62078];

const APPLE_MODELS = [
  [/^iPhone/i, 'iPhone', 'phone', 'iOS'], [/^iPad/i, 'iPad', 'phone', 'iPadOS'], [/^iPod/i, 'iPod touch', 'phone', 'iOS'], [/^Watch/i, 'Apple Watch', 'phone', 'watchOS'],
  [/^AppleTV/i, 'Apple TV', 'tv', 'tvOS'], [/^AudioAccessory/i, 'HomePod', 'speaker', 'audioOS'],
  [/^MacBookPro/i, 'MacBook Pro', 'computer', 'macOS'], [/^MacBookAir/i, 'MacBook Air', 'computer', 'macOS'], [/^MacBook/i, 'MacBook', 'computer', 'macOS'],
  [/^Macmini/i, 'Mac mini', 'computer', 'macOS'], [/^iMac/i, 'iMac', 'computer', 'macOS'], [/^MacPro/i, 'Mac Pro', 'computer', 'macOS'], [/^MacStudio|^Mac1[3-9],/i, 'Mac', 'computer', 'macOS'],
];
const TV_BRANDS = /samsung|lg electronics|\blg\b|sony|bravia|tcl|hisense|philips|panasonic|vizio|sharp|toshiba|xiaomi|skyworth|kalley|challenger|moka|roku|amazon|google|nvidia|haier|jvc/i;
const PHONE_BRANDS = /motorola|samsung|xiaomi|redmi|poco|huawei|honor|oneplus|oppo|vivo|realme|tecno|infinix|itel|transsion|google|nokia|zte|apple/i;
const ROUTER_BRANDS = /tp-link|tplink|mikrotik|ubiquiti|netgear|cisco|huawei|zte|d-link|dlink|asus|linksys|tenda|arris|technicolor|sagemcom|fiberhome|mercusys|aruba|juniper|openwrt/i;
const PRINTER_BRANDS = /brother|epson|canon|hewlett|\bhp\b|lexmark|kyocera|ricoh|xerox|zebra|pantum/i;
const CAMERA_BRANDS = /hikvision|dahua|ezviz|reolink|axis|foscam|amcrest|imou|tapo|wyze|uniview/i;
const CONSOLE_HINTS = /xbox|playstation|ps[345]\b|nintendo|switch/i;

/** La MAC "administrada localmente" (2º dígito 2, 6, A o E) es una MAC privada/aleatoria. */
export function isPrivateMac(mac) { return /^.[26ae]/i.test(String(mac || '')); }

function appleModel(identifier) {
  const hit = APPLE_MODELS.find(([pattern]) => pattern.test(identifier || ''));
  return hit ? { name: hit[1], kind: hit[2], os: hit[3] } : null;
}
const openPorts = host => new Set((host.ports || []).filter(port => port.state === 'open').map(port => Number(port.port)));
const clean = value => String(value || '').replace(/\s+/g, ' ').trim();

/**
 * @param base  resultado de la identificación clásica (huella de SO, hostname, fabricante)
 * @returns base ampliado con category, model, confidence, reasons[]
 */
export function identify(base, host, { isGateway = false, adb = null } = {}) {
  const evidence = host.evidence || {};
  const mdns = evidence.mdns;
  const upnp = evidence.upnp;
  const txt = mdns?.txt || {};
  const services = new Set(mdns?.services || []);
  const ports = openPorts(host);
  const vendor = clean(host.mac_vendor);
  const names = [host.hostname, ...(host.hostnames || []), ...(mdns?.hostnames || []), ...(mdns?.instances || []), evidence.dhcp?.hostname].filter(Boolean).join(' ');
  const result = { ...base, category: null, model: '', brand: base.vendor || '', confidence: 'baja', reasons: [] };
  const score = { alta: 3, media: 2, baja: 1 };
  /** Aplica una conclusión solo si no contradice otra de mayor confianza. */
  const conclude = (confidence, reason, changes = {}) => {
    result.reasons.push({ confidence, text: reason });
    const stronger = score[confidence] > score[result.confidence] || !result.category;
    for (const [key, value] of Object.entries(changes)) {
      if (!value) continue;
      if (stronger || !result[key] || (key === 'os' && /sin determinar/i.test(result.os))) result[key] = value;
    }
    if (score[confidence] > score[result.confidence]) result.confidence = confidence;
  };

  if (base.isLocal) {
    return { ...result, osFamily: familyOf(base.os), category: 'computer', deviceType: 'Este computador', confidence: 'alta', model: '', reasons: [{ confidence: 'alta', text: 'Es este mismo computador: los datos se leyeron directamente del sistema.' }] };
  }
  if (adb) {
    conclude('alta', `Android autorizado por ADB informó su modelo y versión${adb.android_version ? ` (Android ${adb.android_version})` : ''}.`, { category: 'phone', kind: 'android', os: `Android${adb.android_version ? ` ${adb.android_version}` : ''}`, brand: adb.manufacturer || adb.brand, model: adb.model });
  }

  // 1. UPnP: el dispositivo publica su propia ficha (fabricante, modelo y nombre).
  for (const description of upnp?.descriptions || []) {
    const label = clean([description.manufacturer, description.model_name, description.model_number].filter(Boolean).join(' '));
    const text = `${description.device_type} ${description.friendly_name} ${description.model_name} ${description.model_description} ${description.manufacturer}`;
    const changes = { brand: description.manufacturer, model: clean([...new Set([description.model_name, description.model_number].filter(Boolean))].join(' ')), name: description.friendly_name };
    if (/InternetGatewayDevice|WANDevice|WFADevice|router|gateway/i.test(text)) conclude('alta', `UPnP: se anuncia como puerta de enlace de Internet (${label || 'sin modelo'}).`, { ...changes, category: 'router', kind: 'router' });
    else if (CONSOLE_HINTS.test(text)) conclude('alta', `UPnP: se anuncia como consola (${label}).`, { ...changes, category: 'console', kind: 'console' });
    else if (/printer|print/i.test(description.device_type)) conclude('alta', `UPnP: se anuncia como impresora (${label}).`, { ...changes, category: 'printer', kind: 'printer' });
    else if (/sonos|ZonePlayer/i.test(text)) conclude('alta', `UPnP: altavoz Sonos (${label}).`, { ...changes, category: 'speaker', kind: 'speaker' });
    else if (/dial|MediaRenderer|RemoteControlReceiver|tvdevice|\btv\b|television|roku|chromecast|bravia|webos|tizen/i.test(text)) conclude('alta', `UPnP: se anuncia como televisor o reproductor multimedia (${label || description.friendly_name}).`, { ...changes, category: 'tv', kind: 'tv' });
    else if (/MediaServer|nas|diskstation|synology|qnap/i.test(text)) conclude('media', `UPnP: servidor multimedia o NAS (${label}).`, { ...changes, category: 'nas', kind: 'nas' });
    else if (/camera|ipcam/i.test(text)) conclude('alta', `UPnP: cámara IP (${label}).`, { ...changes, category: 'camera', kind: 'camera' });
    else if (label) conclude('media', `UPnP: el dispositivo publica su ficha: ${label}.`, changes);
  }
  const servers = (upnp?.servers || []).join(' ');
  const androidVersion = servers.match(/android\s?-?(\d{1,2})\b/i)?.[1];
  if (androidVersion) conclude('alta', `Su servidor UPnP declara un núcleo de Android ${androidVersion}.`, { os: `Android${result.category === 'tv' ? ' TV' : ''} ${androidVersion}`, kind: result.category === 'tv' ? 'tv' : 'android' });
  else if (/webos/i.test(servers)) conclude('alta', 'Su servidor UPnP declara webOS (televisores LG).', { category: 'tv', kind: 'tv', os: 'webOS', brand: 'LG' });
  else if (/tizen|samsung/i.test(servers) && result.category === 'tv') conclude('alta', 'Su servidor UPnP declara Tizen (televisores Samsung).', { os: 'Tizen', brand: 'Samsung' });
  else if (/roku/i.test(servers)) conclude('alta', 'Su servidor UPnP declara Roku OS.', { category: 'tv', kind: 'tv', os: 'Roku OS', brand: 'Roku' });
  else if (/windows/i.test(servers)) conclude('media', 'Su servidor UPnP declara Microsoft Windows.', { category: 'computer', kind: 'windows', os: 'Windows' });

  // 2. mDNS / Bonjour: servicios y propiedades que el equipo anuncia.
  const cast = txt['_googlecast._tcp'];
  if (cast) {
    const speaker = /home|nest (mini|audio|hub)|speaker/i.test(cast.md || '');
    conclude('alta', `mDNS: anuncia Google Cast como “${cast.fn || cast.md || 'sin nombre'}”, modelo ${cast.md || 'no informado'}${cast.rs ? `; ahora mismo reproduce: ${cast.rs}` : ''}.`, { category: speaker ? 'speaker' : 'tv', kind: speaker ? 'speaker' : 'tv', model: cast.md, name: cast.fn, os: speaker ? 'Cast OS' : result.os && !/sin determinar/i.test(result.os) ? result.os : 'Android TV / Google TV' });
  }
  if (services.has('_androidtvremote2._tcp')) conclude('alta', 'mDNS: ofrece el control remoto de Android TV.', { category: 'tv', kind: 'tv', os: 'Android TV / Google TV' });
  if (services.has('_amzn-wplay._tcp')) conclude('alta', 'mDNS: anuncia el servicio de Amazon Fire TV.', { category: 'tv', kind: 'tv', os: 'Fire OS', brand: 'Amazon', model: 'Fire TV' });
  const airplay = txt['_airplay._tcp'] || txt['_raop._tcp'];
  const info = txt['_device-info._tcp'];
  const appleId = info?.model || airplay?.model || airplay?.am;
  const apple = appleModel(appleId);
  if (apple) conclude('alta', `mDNS: el equipo declara el identificador de modelo Apple “${appleId}” (${apple.name}).`, { category: apple.kind, kind: apple.kind === 'computer' || apple.kind === 'phone' ? 'apple' : apple.kind, os: `${apple.os}${info?.osxvers ? ` (Darwin ${info.osxvers})` : ''}`, brand: 'Apple', model: `${apple.name} · ${appleId}` });
  else if (airplay && (airplay.manufacturer || airplay.model)) conclude('alta', `mDNS: receptor AirPlay de ${airplay.manufacturer || 'fabricante no informado'}, modelo ${airplay.model || 'no informado'}.`, { category: 'tv', kind: 'tv', brand: airplay.manufacturer, model: airplay.model });
  if (services.has('_apple-mobdev2._tcp')) conclude('alta', 'mDNS: anuncia la sincronización Wi-Fi de iOS (apple-mobdev2), exclusiva de iPhone y iPad.', { category: 'phone', kind: 'apple', os: 'iOS / iPadOS', brand: 'Apple' });
  if (services.has('_companion-link._tcp') && !result.category) conclude('media', 'mDNS: anuncia Companion Link, propio de dispositivos Apple.', { kind: 'apple', brand: 'Apple' });
  const printer = txt['_ipp._tcp'] || txt['_ipps._tcp'] || txt['_printer._tcp'] || txt['_pdl-datastream._tcp'];
  if (printer || ['_ipp._tcp', '_ipps._tcp', '_printer._tcp', '_pdl-datastream._tcp', '_uscan._tcp', '_scanner._tcp'].some(service => services.has(service))) {
    conclude('alta', `mDNS: anuncia servicios de impresión${printer?.ty ? ` como “${printer.ty}”` : ''}.`, { category: 'printer', kind: 'printer', brand: printer?.usb_mfg, model: printer?.ty || printer?.usb_mdl || printer?.product?.replace(/[()]/g, '') });
  }
  if (services.has('_sonos._tcp') || services.has('_spotify-connect._tcp') && !result.category) conclude('media', 'mDNS: anuncia reproducción de audio en red (Sonos / Spotify Connect).', { category: 'speaker', kind: 'speaker' });
  if ((services.has('_hap._tcp') || services.has('_homekit._tcp') || services.has('_matter._tcp')) && !result.category) conclude('media', 'mDNS: accesorio de hogar inteligente (HomeKit / Matter).', { category: 'iot', kind: 'iot', model: txt['_hap._tcp']?.md });
  if (services.has('_adb-tls-connect._tcp')) conclude('alta', 'mDNS: tiene activa la depuración inalámbrica de Android.', { category: result.category || 'phone', kind: result.kind === 'tv' ? 'tv' : 'android', os: /android/i.test(result.os) ? result.os : 'Android' });
  if ((services.has('_smb._tcp') || services.has('_afpovertcp._tcp')) && !result.category) conclude('baja', 'mDNS: comparte archivos en la red (SMB/AFP).', { category: 'computer' });

  // 2b. DHCP: cómo se presentó el equipo al pedir su dirección. Es la pista más fiable para distinguir Android de iOS.
  const dhcp = evidence.dhcp;
  if (dhcp) {
    const vendorClass = dhcp.vendor_class || '';
    const params = dhcp.params || [];
    const has = code => params.includes(code);
    const android = vendorClass.match(/^android-dhcp-(\d+)/i);
    const isTv = result.category === 'tv';
    if (android) conclude('alta', `DHCP: al conectarse a la red se presentó como “${vendorClass}”, la firma del cliente DHCP de Android ${android[1]}.`, { category: result.category || 'phone', kind: isTv ? 'tv' : 'android', os: `Android${isTv ? ' TV' : ''} ${android[1]}` });
    else if (/^(dhcpcd|android)/i.test(vendorClass)) conclude('alta', `DHCP: se presentó como “${vendorClass}”, cliente DHCP de versiones antiguas de Android.`, { category: result.category || 'phone', kind: isTv ? 'tv' : 'android', os: 'Android' });
    else if (/^MSFT/i.test(vendorClass)) conclude('alta', `DHCP: se presentó como “${vendorClass}”, la firma del cliente DHCP de Windows.`, { category: result.category || 'computer', kind: 'windows', os: /windows \d/i.test(result.os) ? result.os : 'Windows' });
    else if (/udhcp|busybox/i.test(vendorClass)) conclude('media', `DHCP: usa el cliente “${vendorClass}” de BusyBox, propio de Linux embebido (routers, cámaras, IoT).`, { os: 'Linux embebido' });
    else if (!vendorClass && has(252) && has(119) && has(121)) {
      const mac = has(95) || has(44) || has(46);
      conclude('alta', `DHCP: pidió la lista de parámetros característica de Apple (${params.join(', ')}) sin clase de fabricante, como hacen ${mac ? 'los Mac' : 'iPhone y iPad'}.`,
        mac ? { category: result.category || 'computer', kind: 'apple', os: 'macOS', brand: 'Apple' } : { category: result.category || 'phone', kind: isTv ? 'tv' : 'apple', os: 'iOS / iPadOS', brand: 'Apple' });
    }
    if (dhcp.hostname) { result.reasons.push({ confidence: 'media', text: `DHCP: al pedir su dirección dijo llamarse “${dhcp.hostname}”.` }); if (!result.name && !host.hostname) result.name = dhcp.hostname; }
  }

  // 3. Puertos firma detectados por Nmap.
  if (ports.has(62078)) conclude('alta', 'Puerto 62078 abierto: servicio lockdownd, presente solo en iPhone y iPad.', { category: 'phone', kind: 'apple', os: 'iOS / iPadOS', brand: 'Apple' });
  if (ports.has(5555) && result.category !== 'tv') conclude('media', 'Puerto 5555 abierto: depuración ADB de Android.', { category: result.category || 'phone', kind: 'android', os: /android/i.test(result.os) ? result.os : 'Android' });
  if (ports.has(8060)) conclude('alta', 'Puerto 8060 abierto: API de control de Roku.', { category: 'tv', kind: 'tv', os: 'Roku OS', brand: 'Roku' });
  if ((ports.has(8001) || ports.has(8002)) && /samsung/i.test(`${vendor} ${names}`)) conclude('alta', 'Puertos 8001/8002 abiertos en un equipo Samsung: API de Smart TV (Tizen).', { category: 'tv', kind: 'tv', os: 'Tizen', brand: 'Samsung' });
  if ((ports.has(3000) || ports.has(3001)) && /lg/i.test(`${vendor} ${names}`)) conclude('alta', 'Puertos 3000/3001 abiertos en un equipo LG: API de webOS TV.', { category: 'tv', kind: 'tv', os: 'webOS', brand: 'LG' });
  if ((ports.has(8008) || ports.has(8009)) && !cast) conclude('media', 'Puertos 8008/8009 abiertos: protocolo Google Cast (Chromecast o Android TV).', { category: 'tv', kind: 'tv', os: 'Android TV / Google TV' });
  if ((ports.has(9100) || ports.has(631) || ports.has(515)) && result.category !== 'computer') conclude('media', 'Puertos de impresión abiertos (9100 / 631 / 515).', { category: 'printer', kind: 'printer' });
  if (ports.has(554) && !['tv', 'computer'].includes(result.category)) conclude('media', 'Puerto 554 abierto: transmisión de vídeo RTSP, típica de cámaras IP y grabadores.', { category: 'camera', kind: 'camera' });
  if (ports.has(135) || ports.has(3389) || (ports.has(445) && ports.has(139) && evidence.ttl === 128)) conclude(ports.has(135) ? 'alta' : 'media', `Puertos de Windows abiertos (${[135, 139, 445, 3389].filter(port => ports.has(port)).join(', ')}): RPC, SMB o Escritorio remoto.`, { category: 'computer', kind: 'windows', os: /windows/i.test(result.os) ? result.os : 'Windows' });
  if (ports.has(548) || (ports.has(5000) && ports.has(7000))) conclude('media', 'Puertos de macOS abiertos (AFP o receptor AirPlay del Mac).', { category: 'computer', kind: 'apple', os: 'macOS', brand: 'Apple' });
  if (ports.has(32400)) conclude('baja', 'Puerto 32400 abierto: servidor multimedia Plex.', {});

  // 4. Identificación clásica: huella de sistema operativo de Nmap, nombre anunciado y fabricante.
  if (base.accuracy != null) conclude(base.accuracy >= 90 ? 'media' : 'baja', `Huella de red de Nmap: ${base.os} (${base.accuracy}% de coincidencia).`, { os: base.os, category: /router/.test(base.deviceType) ? 'router' : /tel[eé]fono/.test(base.deviceType) ? 'phone' : /impresora/.test(base.deviceType) ? 'printer' : /comput/.test(base.deviceType) ? 'computer' : null });
  if (/iphone|ipad/i.test(names)) conclude('media', `Su nombre de red contiene “${names.match(/iphone|ipad/i)[0]}”.`, { category: 'phone', kind: 'apple', os: 'iOS / iPadOS', brand: 'Apple' });
  else if (/galaxy|redmi|poco|xiaomi|moto[ -]?[gex]|pixel|huawei|honor|oppo|realme|infinix|tecno|android/i.test(names)) conclude('media', `Su nombre de red (“${clean(host.hostname || names).slice(0, 40)}”) corresponde a un teléfono Android.`, { category: 'phone', kind: 'android', os: /android/i.test(result.os) ? result.os : 'Android', model: clean(host.hostname).replace(/[-_]/g, ' ') });
  else if (/macbook|imac|mac-?mini/i.test(names)) conclude('media', 'Su nombre de red corresponde a un Mac.', { category: 'computer', kind: 'apple', os: 'macOS', brand: 'Apple' });
  else if (/desktop-|laptop-|-pc\b|\bpc-|win-/i.test(names)) conclude('media', `Su nombre de red (“${clean(host.hostname).slice(0, 40)}”) sigue el patrón de un equipo Windows.`, { category: 'computer', kind: 'windows', os: /windows/i.test(result.os) ? result.os : 'Windows' });
  else if (/\btv\b|bravia|smart-?tv|roku|chromecast|firetv|fire-tv|webos|tizen/i.test(names)) conclude('media', 'Su nombre de red corresponde a un televisor o reproductor.', { category: 'tv', kind: 'tv' });
  else if (CONSOLE_HINTS.test(names)) conclude('media', 'Su nombre de red corresponde a una consola de videojuegos.', { category: 'console', kind: 'console' });

  if (isGateway) conclude('alta', 'Es la puerta de enlace configurada en este computador: el router de la red.', { category: 'router', kind: 'router' });
  if (vendor) {
    if (CAMERA_BRANDS.test(vendor)) conclude('media', `Fabricante de la tarjeta de red: ${vendor}, marca de cámaras de seguridad.`, { category: 'camera', kind: 'camera', brand: vendor });
    else if (PRINTER_BRANDS.test(vendor) && (result.category === 'printer' || !result.category)) conclude('baja', `Fabricante de la tarjeta de red: ${vendor}, marca habitual de impresoras.`, { category: 'printer', kind: 'printer', brand: vendor });
    else if (/nintendo|sony interactive|microsoft.*xbox/i.test(vendor)) conclude('media', `Fabricante de la tarjeta de red: ${vendor}.`, { category: 'console', kind: 'console', brand: vendor });
    else if (/espressif|tuya|shelly|sonoff|itead|broadlink|ring|nest labs/i.test(vendor)) conclude('media', `Fabricante de la tarjeta de red: ${vendor}, chips habituales de enchufes, bombillos y sensores inteligentes.`, { category: 'iot', kind: 'iot', brand: vendor });
    else if (/synology|qnap|asustor|terramaster|western digital|buffalo/i.test(vendor)) conclude('media', `Fabricante de la tarjeta de red: ${vendor}, marca de almacenamiento en red (NAS).`, { category: 'nas', kind: 'nas', brand: vendor });
    else if (/raspberry/i.test(vendor)) conclude('media', 'Fabricante de la tarjeta de red: Raspberry Pi.', { category: 'computer', kind: 'linux', os: /sin determinar/i.test(result.os) ? 'Linux (Raspberry Pi OS probable)' : result.os, brand: 'Raspberry Pi' });
    else if (ROUTER_BRANDS.test(vendor) && !result.category) conclude('baja', `Fabricante de la tarjeta de red: ${vendor}, marca habitual de equipos de red.`, { category: 'router', kind: 'router', brand: vendor });
    else if (/apple/i.test(vendor) && !result.category) conclude('baja', 'Fabricante de la tarjeta de red: Apple (iPhone, iPad, Mac o Apple TV).', { kind: 'apple', brand: 'Apple' });
    else if (TV_BRANDS.test(vendor) && result.category === 'tv') conclude('baja', `Fabricante de la tarjeta de red: ${vendor}.`, { brand: result.brand || vendor });
    else if (PHONE_BRANDS.test(vendor) && !result.category) conclude('baja', `Fabricante de la tarjeta de red: ${vendor}, marca de teléfonos.`, { category: 'phone', kind: 'phone', brand: vendor });
    else conclude('baja', `Fabricante de la tarjeta de red (prefijo de la MAC): ${vendor}.`, { brand: result.brand || vendor });
  }

  // 5. Pistas débiles: TTL de la respuesta al ping y MAC privada.
  if (evidence.ttl) {
    const family = evidence.ttl > 128 ? 'equipos de red y algunos dispositivos embebidos' : evidence.ttl > 64 ? 'Windows' : 'Linux, Android, iOS y macOS';
    const changes = {};
    if (evidence.ttl > 64 && evidence.ttl <= 128 && !result.category) Object.assign(changes, { category: 'computer', kind: 'windows', os: 'Windows (probable)' });
    conclude('baja', `Respondió al ping con TTL ${evidence.ttl}, valor inicial típico de ${family}.`, changes);
  }
  if (isPrivateMac(host.mac)) {
    const changes = !result.category ? { category: 'phone', kind: result.kind === 'device' ? 'phone' : result.kind } : {};
    conclude('baja', 'Usa una MAC privada (aleatoria), función activada por defecto en iPhone, iPad y Android recientes; por eso no se puede leer su fabricante.', changes);
  }

  if (host.os_unreliable) result.reasons.push({ confidence: 'baja', text: 'Nmap intentó la huella de sistema operativo, pero el equipo no tiene ningún puerto abierto y sin eso la huella no es fiable: se descartó.' });
  // 6. Sistema operativo por descarte, cuando nada lo confirmó directamente.
  const undetermined = () => /sin determinar/i.test(result.os);
  const appleServices = ['_rdlink._tcp', '_companion-link._tcp', '_remotepairing._tcp', '_apple-mobdev2._tcp', '_airplay._tcp', '_raop._tcp', '_sleep-proxy._udp', '_touch-able._tcp', '_device-info._tcp'].filter(service => services.has(service));
  if (appleServices.length && undetermined()) {
    const mobile = isPrivateMac(host.mac) || result.category === 'phone';
    conclude('media', `mDNS: responde a servicios exclusivos de Apple (${appleServices.join(', ')}).`, mobile ? { category: 'phone', kind: 'apple', os: 'iOS / iPadOS', brand: 'Apple' } : { kind: 'apple', os: 'iOS o macOS', brand: 'Apple' });
    result.kind = 'apple';
  }
  if (result.category === 'phone' && undetermined()) {
    if (host.signature_scan) {
      result.os = 'Android (probable)'; result.kind = 'android';
      result.reasons.push({ confidence: 'baja', text: 'Sistema por descarte: se comporta como un celular y no mostró ninguna señal de Apple (el puerto 62078 de iPhone no respondió y no anuncia servicios Bonjour), así que lo más probable es Android.' });
    } else result.os = 'Android o iOS';
  }
  if (undetermined() && evidence.ttl) {
    if (evidence.ttl > 64 && evidence.ttl <= 128) { result.os = 'Windows (probable)'; if (result.kind === 'device' || result.kind === 'computer') result.kind = 'windows'; }
    else if (evidence.ttl <= 64) {
      result.os = ports.has(22) ? 'Linux (probable)' : 'Linux o derivado (probable)';
      if (result.kind === 'device' || result.kind === 'computer') result.kind = result.category === 'computer' || ports.has(22) ? 'linux' : result.kind;
      result.reasons.push({ confidence: 'baja', text: `Sistema por descarte: TTL ${evidence.ttl} sin señales de Windows, Apple ni celular${ports.has(22) ? ' y con SSH abierto' : ''}. Lo habitual es un sistema basado en Linux (routers, televisores, IoT, servidores).` });
    } else { result.os = 'Sistema embebido de red (probable)'; }
  }
  result.osFamily = familyOf(result.os);

  if (!result.category) { result.category = base.kind === 'router' ? 'router' : ['windows', 'linux', 'ubuntu', 'debian', 'arch', 'computer'].includes(base.kind) ? 'computer' : base.kind === 'phone' || base.kind === 'android' ? 'phone' : 'device'; }
  if (!result.reasons.length) result.reasons.push({ confidence: 'baja', text: 'El equipo respondió al descubrimiento pero no anunció nada sobre sí mismo. Un escaneo profundo puede aportar más pistas.' });
  if (result.kind === 'device' && ['tv', 'printer', 'console', 'camera', 'speaker', 'iot', 'nas', 'phone', 'router', 'computer'].includes(result.category)) result.kind = result.category;
  result.vendor = result.brand || base.vendor || '';
  result.deviceType = CATEGORY_LABELS[result.category] || base.deviceType;
  result.model = clean(result.model);
  result.reasons.sort((a, b) => score[b.confidence] - score[a.confidence]);
  return result;
}
