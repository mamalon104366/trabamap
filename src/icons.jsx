import React from 'react';

const drawings = {
  scan: <><circle cx="12" cy="12" r="8.2"/><circle cx="12" cy="12" r="3.1"/><path d="M12 2.7v3M21.3 12h-3M12 21.3v-3M2.7 12h3"/><path d="m12 12 5.6-5.6"/></>,
  history: <><path d="M4.1 8.2A8.2 8.2 0 1 1 3.8 14"/><path d="M3.5 4.7v4.8h4.8M12 7.3v5l3.1 1.9"/></>,
  activity: <><path d="M3 12h3.8l2.1-5.4 4.2 10.8 2.2-5.4H21"/><path d="M4.4 5.3A9 9 0 1 1 3 15.5"/></>,
  'chevron-right': <path d="m9 5 7 7-7 7"/>,
  'chevron-left': <path d="m15 5-7 7 7 7"/>,
  'chevron-down': <path d="m5 9 7 7 7-7"/>,
  refresh: <><path d="M20 7v5h-5M4 17v-5h5"/><path d="M5.7 9a7 7 0 0 1 11.8-2L20 12M4 12l2.5 5a7 7 0 0 0 11.8-2"/></>,
  lock: <><rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3"/></>,
  network: <><rect x="9" y="3" width="6" height="6" rx="1"/><rect x="3" y="16" width="6" height="5" rx="1"/><rect x="15" y="16" width="6" height="5" rx="1"/><path d="M12 9v3M6 16v-4h12v4M18 12v4"/></>,
  globe: <><circle cx="12" cy="12" r="9"/><path d="M3.5 12h17M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18M5.2 6.3h13.6M5.2 17.7h13.6"/></>,
  play: <path d="m8 5 11 7-11 7z"/>,
  stop: <rect x="6" y="6" width="12" height="12" rx="2"/>,
  sliders: <><path d="M4 7h9M17 7h3M4 17h3M11 17h9"/><circle cx="15" cy="7" r="2"/><circle cx="9" cy="17" r="2"/></>,
  filter: <><path d="M4 5h16l-6.5 7.4v5l-3 1.6v-6.6z"/></>,
  zap: <path d="m13.5 2.8-8 10.1h6l-1 8.3 8-10.1h-6z"/>,
  'shield-alert': <><path d="M12 3 20 6v5.3c0 4.5-3.2 7.8-8 9.7-4.8-1.9-8-5.2-8-9.7V6z"/><path d="M12 7v5M12 15.5h.01"/></>,
  wifi: <><path d="M3.5 9.2a13 13 0 0 1 17 0M6.5 12.4a8.2 8.2 0 0 1 11 0M9.5 15.5a3.8 3.8 0 0 1 5 0M12 19h.01"/></>,
  check: <path d="m5 12.5 4.4 4.2L19 7"/>,
  alert: <><path d="M10.4 4.1 2.8 17.2A1.9 1.9 0 0 0 4.5 20h15a1.9 1.9 0 0 0 1.7-2.8L13.6 4.1a1.9 1.9 0 0 0-3.2 0Z"/><path d="M12 9v4.5M12 17h.01"/></>,
  x: <path d="m6 6 12 12M18 6 6 18"/>,
  loader: <><path d="M20 12a8 8 0 0 1-8 8"/><path d="M4 12a8 8 0 0 1 8-8"/></>,
  server: <><rect x="3" y="4" width="18" height="7" rx="1.5"/><rect x="3" y="13" width="18" height="7" rx="1.5"/><path d="M7 7.5h.01M7 16.5h.01M11 7.5h6M11 16.5h6"/></>,
  copy: <><rect x="8" y="8" width="12" height="13" rx="2"/><path d="M16 8V5a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2h2"/></>,
  download: <><path d="M12 3v12M7 10l5 5 5-5M4 20h16"/></>,
  table: <><rect x="3" y="4" width="18" height="16" rx="1.5"/><path d="M3 9h18M9 9v11m6-11v11M3 14h18"/></>,
  external: <><path d="M13 5h6v6M19 5l-9 9"/><path d="M18 13v5a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5"/></>,
  code: <><path d="m8 7-5 5 5 5M16 7l5 5-5 5M14 4l-4 16"/></>,
  search: <><circle cx="10.8" cy="10.8" r="6.6"/><path d="m16 16 5 5"/></>,
  terminal: <><rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3M13 15h4"/></>,
  'hard-drive': <><rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 14h18M7 9h.01M7 16.5h.01M11 16.5h.01"/></>,
  'arrow-right': <><path d="M4 12h15M13 5l7 7-7 7"/></>,
  'arrow-up-right': <><path d="M7 17 17 7M8 7h9v9"/></>,
  'arrow-left': <><path d="M20 12H5M11 5l-7 7 7 7"/></>,
  file: <><path d="M6 3h8l5 5v13H6z"/><path d="M14 3v5h5M9 13h7M9 17h7"/></>,
  clock: <><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3.5 2"/></>,
  'shield-check': <><path d="M12 3 20 6v5.3c0 4.5-3.2 7.8-8 9.7-4.8-1.9-8-5.2-8-9.7V6z"/><path d="m8.5 12.2 2.3 2.2 4.8-5"/></>,
  info: <><circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 7.5h.01"/></>,
  panel: <><rect x="3" y="4" width="18" height="16" rx="3"/><path d="M9 4v16M15 10l-2 2 2 2"/></>,
  book: <><path d="M5 4h11a3 3 0 0 1 3 3v13H8a3 3 0 0 1-3-3z"/><path d="M5 17a3 3 0 0 1 3-3h11M9 8h6"/></>,
  map: <><circle cx="12" cy="12" r="2.6"/><circle cx="4.5" cy="5.5" r="1.9"/><circle cx="19.5" cy="5.5" r="1.9"/><circle cx="4.5" cy="18.5" r="1.9"/><circle cx="19.5" cy="18.5" r="1.9"/><path d="m6 7 4 3.4M18 7l-4 3.4M6 17l4-3.4M18 17l-4-3.4"/></>,
  list: <><path d="M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01"/></>,
  updown: <><path d="m7 9 5-5 5 5M7 15l5 5 5-5"/></>,
  help: <><circle cx="12" cy="12" r="9"/><path d="M9.6 9.3a2.5 2.5 0 1 1 3.6 2.3c-.8.4-1.2 1-1.2 1.9M12 17h.01"/></>,
  sparkle: <><path d="M12 3.5 13.8 9l5.7 1.9-5.7 1.9L12 18.5l-1.8-5.7-5.7-1.9L10.2 9z"/><path d="M19 3v3M17.5 4.5h3M5 17v3M3.5 18.5h3"/></>,
  router: <><rect x="3" y="12" width="18" height="8" rx="2"/><path d="M7 16h.01M11 16h.01M8 12V8m8 4V8M5.5 5.5a9 9 0 0 1 13 0"/></>,
  sun: <><circle cx="12" cy="12" r="4"/><path d="M12 2.5v2.2M12 19.3v2.2M2.5 12h2.2M19.3 12h2.2M5.3 5.3l1.6 1.6M17.1 17.1l1.6 1.6M5.3 18.7l1.6-1.6M17.1 6.9l1.6-1.6"/></>,
  moon: <path d="M20 14.2A8.3 8.3 0 0 1 9.8 4a8.3 8.3 0 1 0 10.2 10.2Z"/>,
  cpu: <><rect x="6" y="6" width="12" height="12" rx="2"/><path d="M10 10h4v4h-4zM9 3v3m6-3v3M9 18v3m6-3v3M3 9h3m-3 6h3m12-6h3m-3 6h3"/></>,
};

export function Icon({ name, size = 18, className = '', strokeWidth = 1.65 }) {
  return <svg className={`icon ${className}`.trim()} width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false">{drawings[name] || drawings.scan}</svg>;
}

export function LogoMark({ size = 24, className = '' }) {
  // Marca TrabaMap: la "T" angular del logo de la empresa, trazada como vector.
  return <svg className={`logo-mark ${className}`.trim()} width={size} height={size} viewBox="0 0 261 261" fill="currentColor" aria-hidden="true" focusable="false">
    <path d={LOGO_PATH}/>
  </svg>;
}

export const LOGO_PATH = 'M22 27H232L149 100V172L154 182L130 208L111 221L92 207L120 184V95L165 50H97L76 71Z';

export function LogoTile({ size = 40, className = '' }) {
  return <span className={`logo-tile ${className}`.trim()} style={{ width: size, height: size }}><LogoMark size={Math.round(size * 0.72)}/></span>;
}
