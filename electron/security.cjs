// Parámetros de seguridad de TrabaMap que se deciden antes de lanzar un escaneo.
// Se evalúan en el proceso principal: la ventana no puede saltárselos.
const fs = require('node:fs');

const DEFAULTS = { privateOnly: true, confirmIntrusive: true, maxHosts: 1024, allowInsaneTiming: false };
const LIMITS = { maxHosts: [16, 65536] };

function loadSettings(file) {
  try {
    const stored = JSON.parse(fs.readFileSync(file, 'utf8'));
    return sanitize({ ...DEFAULTS, ...stored });
  } catch { return { ...DEFAULTS }; }
}
function sanitize(value) {
  const maxHosts = Math.round(Number(value.maxHosts));
  return {
    privateOnly: value.privateOnly !== false,
    confirmIntrusive: value.confirmIntrusive !== false,
    allowInsaneTiming: value.allowInsaneTiming === true,
    maxHosts: Number.isFinite(maxHosts) ? Math.min(LIMITS.maxHosts[1], Math.max(LIMITS.maxHosts[0], maxHosts)) : DEFAULTS.maxHosts,
  };
}
function saveSettings(file, value) {
  const clean = sanitize({ ...DEFAULTS, ...value });
  fs.writeFileSync(file, JSON.stringify(clean, null, 2), 'utf8');
  return clean;
}

const PRIVATE_V4 = /^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.)/;
const LOCAL_NAME = /^(localhost|[a-z0-9_-]+|.+\.(local|lan|home|localdomain|internal|intranet))$/i;

/** Clasifica un objetivo escrito por el usuario y estima cuántas direcciones abarca. */
function classifyTarget(token) {
  const [address, prefix] = token.split('/');
  if (/^[0-9.*,-]+$/.test(address) && address.includes('.')) {
    const size = prefix !== undefined ? 2 ** Math.max(0, 32 - Number(prefix)) : address.split('.').reduce((total, octet) => {
      if (octet === '*') return total * 256;
      const range = octet.match(/^(\d+)-(\d+)$/);
      if (range) return total * Math.max(1, Number(range[2]) - Number(range[1]) + 1);
      return total * octet.split(',').length;
    }, 1);
    return { token, scope: PRIVATE_V4.test(address) ? 'private' : 'public', hosts: size };
  }
  if (address.includes(':')) {
    const local = /^(::1$|fe[89ab]|f[cd])/i.test(address);
    return { token, scope: local ? 'private' : 'public', hosts: prefix !== undefined ? 2 ** Math.min(20, Math.max(0, 128 - Number(prefix))) : 1 };
  }
  return { token, scope: LOCAL_NAME.test(address) ? 'private' : 'public', hosts: 1 };
}

const INTRUSIVE_SCRIPT = /--script[= ]\s*"?[^"]*\b(vuln\w*|auth|malware|http-enum|smb-enum-shares|smb-vuln[\w-]*|ssl-heartbleed|ssl-poodle|vulners)\b/i;

/** @returns {{blocked: string[], needs: {code: string, title: string, text: string}[], summary: object}} */
function evaluate(target, options, settings) {
  const tokens = String(target || '').split(/\s+/).filter(Boolean).map(classifyTarget);
  const external = tokens.filter(item => item.scope === 'public');
  const hosts = tokens.reduce((total, item) => total + item.hosts, 0);
  const blocked = [];
  const needs = [];
  if (hosts > settings.maxHosts) blocked.push(`El objetivo abarca unas ${hosts.toLocaleString('es-CO')} direcciones y el límite configurado en Seguridad es ${settings.maxHosts.toLocaleString('es-CO')}. Reduce el rango.`);
  if (Number(options?.timing) >= 5 && !settings.allowInsaneTiming) blocked.push('La velocidad máxima (T5) está desactivada en Seguridad: puede saturar la red y perder resultados. Usa T4 o actívala allí.');
  if (external.length && settings.privateOnly) {
    needs.push({ code: 'external', title: 'El objetivo está fuera de tu red local', text: `${external.map(item => item.token).join(', ')} no es una dirección privada. Escanear equipos ajenos sin permiso puede ser ilegal. Continúa solo si el equipo es tuyo o tienes autorización escrita de su dueño.` });
  }
  const intrusive = options?.scripts === 'vuln' || options?.aggressive === true || INTRUSIVE_SCRIPT.test(String(options?.custom_args || ''));
  if (intrusive && settings.confirmIntrusive) {
    needs.push({ code: 'intrusive', title: 'Este escaneo es intrusivo', text: 'Envía peticiones que prueban fallos, accesos o rutas del servicio. No lo rompe, pero deja rastro en sus registros y un sistema de detección puede marcarlo como ataque. Úsalo solo en equipos propios o autorizados.' });
  }
  return { blocked, needs, summary: { hosts, external: external.map(item => item.token), intrusive } };
}

module.exports = { DEFAULTS, loadSettings, saveSettings, evaluate, classifyTarget };
