import React, { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { Icon, LogoTile } from './icons.jsx';
import { PROFILES, PORT_STATES, RISKS, SCAN_TYPES, OPTION_HELP, GLOSSARY, GUIDE_SECTIONS, explainCommand, needsAdmin } from './knowledge.js';

export const NAV_GROUPS = [
  { label: 'General', items: [
    { id: 'scan', icon: 'scan', label: 'Escáner' },
    { id: 'network', icon: 'network', label: 'Dispositivos' },
    { id: 'catalog', icon: 'list', label: 'Catálogo Nmap' },
  ] },
  { label: 'Análisis', items: [
    { id: 'history', icon: 'history', label: 'Historial' },
    { id: 'logs', icon: 'activity', label: 'Actividad' },
  ] },
  { label: 'Sistema', items: [
    { id: 'security', icon: 'shield-check', label: 'Seguridad' },
    { id: 'guide', icon: 'book', label: 'Guía' },
  ] },
];
export const VIEW_LABELS = Object.fromEntries(NAV_GROUPS.flatMap(group => group.items.map(item => [item.id, item.label])));

const initials = name => String(name || 'TM').replace(/[^\p{L}\p{N} ._-]/gu, '').split(/[\s._-]+/).filter(Boolean).slice(0, 2).map(part => part[0]).join('').toUpperCase() || 'TM';

export function Sidebar({ view, go, collapsed, setCollapsed, counts, system, isReady, hasNmap, busy, onDiscover, onSearch, onRefresh, interfaces, activeAddress, setActiveAddress, theme, toggleTheme }) {
  const [menuOpen, setMenuOpen] = useState(false);
  const userRef = useRef(null);
  const navRef = useRef(null);
  const [indicator, setIndicator] = useState(null);
  // El resaltado de la sección activa es una sola pieza que se desliza de un elemento a otro.
  useLayoutEffect(() => {
    const active = navRef.current?.querySelector('.sb-item.is-active');
    setIndicator(active ? { top: active.offsetTop, height: active.offsetHeight } : null);
  }, [view, collapsed]);
  const userName = String(system?.local_inventory?.user_name || '').split('\\').pop() || system?.hostname || 'Equipo local';
  useEffect(() => {
    if (!menuOpen) return undefined;
    const close = event => { if (event.key === 'Escape' || (event.type === 'mousedown' && !userRef.current?.contains(event.target))) setMenuOpen(false); };
    window.addEventListener('mousedown', close); window.addEventListener('keydown', close);
    return () => { window.removeEventListener('mousedown', close); window.removeEventListener('keydown', close); };
  }, [menuOpen]);

  return <aside className={`sidebar ${collapsed ? 'is-collapsed' : ''}`}>
    <div className="sb-head">
      <button className="sb-brand" onClick={() => go('scan')} title="TrabaMap · ir al escáner" aria-label="TrabaMap, ir al escáner">
        <LogoTile size={38}/><span className="sb-brand-text"><b>TrabaMap</b><small>Explorador de red</small></span>
      </button>
      <button className="sb-collapse" onClick={() => setCollapsed(value => !value)} title={collapsed ? 'Expandir menú' : 'Contraer menú'} aria-label={collapsed ? 'Expandir menú' : 'Contraer menú'}><Icon name="panel" size={18}/></button>
    </div>

    <button className="sb-search" onClick={onSearch} title="Buscar (Ctrl+K)" aria-label="Buscar">
      <Icon name="search" size={17}/><span>Buscar…</span><kbd>Ctrl</kbd><kbd>K</kbd>
    </button>

    <nav className="sb-nav" aria-label="Secciones" ref={navRef}>
      <span className="sb-indicator" aria-hidden="true" style={indicator ? { transform: `translateY(${indicator.top}px)`, height: indicator.height, opacity: 1 } : { opacity: 0 }}/>
      {NAV_GROUPS.map(group => <div className="sb-group" key={group.label}>
        <span className="sb-group-label">{group.label}</span>
        {group.items.map(item => {
          const count = counts[item.id] || 0;
          return <button key={item.id} className={`sb-item ${view === item.id ? 'is-active' : ''}`} onClick={() => go(item.id)} title={item.label} aria-current={view === item.id ? 'page' : undefined}>
            <Icon name={item.icon} size={19}/><span className="sb-item-label">{item.label}</span>
            {count > 0 && <span className="sb-count">{count > 99 ? '99+' : count}</span>}
          </button>;
        })}
      </div>)}
      <div className="sb-group">
        <a className="sb-item" href="https://nmap.org/man/es/index.html" target="_blank" rel="noreferrer" title="Manual de Nmap"><Icon name="external" size={19}/><span className="sb-item-label">Manual de Nmap</span></a>
      </div>
    </nav>

    <div className="sb-bottom">
      <div className={`sb-card ${isReady ? hasNmap ? '' : 'is-partial' : 'is-off'}`}>
        <div className="sb-card-title"><Icon name="sparkle" size={18}/><b>Motor <span>{hasNmap || !isReady ? 'Nmap' : 'integrado'}</span></b><i className="status-dot" title={isReady ? 'Nmap conectado' : 'Nmap no disponible'}/></div>
        <p>{hasNmap ? `Versión ${system.nmap} lista. Descubre qué equipos hay conectados a tu red.` : isReady ? 'Nmap no está instalado. TrabaMap usa su motor integrado: equipos y puertos TCP. Instala Nmap para tenerlo todo.' : system?.engine_error || 'Nmap no aparece instalado. Instálalo desde nmap.org y pulsa comprobar.'}</p>
        <button className="btn-primary" onClick={isReady ? onDiscover : onRefresh} disabled={busy} title={isReady ? 'Buscar dispositivos en la red local' : 'Volver a comprobar Nmap'}>
          <Icon name={isReady ? 'wifi' : 'refresh'} size={16}/><span>{busy ? 'Escaneo en curso…' : isReady ? 'Buscar dispositivos' : 'Comprobar de nuevo'}</span>
        </button>
        {isReady && !hasNmap && <a className="sb-card-link" href="https://nmap.org/download.html" target="_blank" rel="noreferrer">Obtener Nmap en nmap.org</a>}
      </div>

      <div className="sb-user-wrap" ref={userRef}>
        {menuOpen && <div className="sb-user-menu" role="menu">
          <span className="sb-menu-label">Interfaz de red activa</span>
          {interfaces.length ? interfaces.map(item => <button key={item.address} role="menuitemradio" aria-checked={item.address === activeAddress} className={item.address === activeAddress ? 'is-active' : ''} onClick={() => { setActiveAddress(item.address); setMenuOpen(false); }}>
            <Icon name="wifi" size={15}/><span><b>{item.name}</b><small>{item.address} · {item.network || item.cidr}</small></span>{item.address === activeAddress && <Icon name="check" size={14}/>}
          </button>) : <p>No se detectó ninguna red conectada.</p>}
          <button role="menuitem" onClick={toggleTheme}><Icon name={theme === 'light' ? 'moon' : 'sun'} size={15}/><span><b>{theme === 'light' ? 'Cambiar a tema oscuro' : 'Cambiar a tema claro'}</b></span></button>
          <button role="menuitem" onClick={() => { onRefresh(); setMenuOpen(false); }}><Icon name="refresh" size={15}/><span><b>Actualizar datos del equipo</b></span></button>
        </div>}
        <button className="sb-user" onClick={() => setMenuOpen(value => !value)} aria-haspopup="menu" aria-expanded={menuOpen} title={`${userName} · ${activeAddress || 'sin red'}`}>
          <span className="sb-avatar">{initials(userName)}</span>
          <span className="sb-user-text"><b>{userName}</b><small>{system?.hostname ? `${system.hostname} · ` : ''}{activeAddress || 'Sin red'}</small></span>
          <Icon name="updown" size={16}/>
        </button>
      </div>
    </div>
  </aside>;
}

export function CommandPalette({ open, onClose, entries }) {
  const [query, setQuery] = useState('');
  const [cursor, setCursor] = useState(0);
  const inputRef = useRef(null);
  const listRef = useRef(null);
  const results = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return (needle ? entries.filter(entry => `${entry.title} ${entry.hint || ''} ${entry.group}`.toLowerCase().includes(needle)) : entries.filter(entry => entry.pinned)).slice(0, 40);
  }, [entries, query]);
  useEffect(() => { if (open) { setQuery(''); setCursor(0); setTimeout(() => inputRef.current?.focus(), 20); } }, [open]);
  useEffect(() => setCursor(0), [query]);
  useEffect(() => { listRef.current?.querySelector('.is-cursor')?.scrollIntoView({ block: 'nearest' }); }, [cursor]);
  if (!open) return null;
  const run = entry => { if (!entry) return; onClose(); entry.run(); };
  const onKey = event => {
    if (event.key === 'Escape') onClose();
    else if (event.key === 'ArrowDown') { event.preventDefault(); setCursor(value => Math.min(results.length - 1, value + 1)); }
    else if (event.key === 'ArrowUp') { event.preventDefault(); setCursor(value => Math.max(0, value - 1)); }
    else if (event.key === 'Enter') { event.preventDefault(); run(results[cursor]); }
  };
  let lastGroup = '';
  return <div className="palette-scrim" onMouseDown={onClose}>
    <div className="palette" role="dialog" aria-modal="true" aria-label="Buscar en TrabaMap" onMouseDown={event => event.stopPropagation()}>
      <label className="palette-input"><Icon name="search" size={18}/><input ref={inputRef} value={query} onChange={event => setQuery(event.target.value)} onKeyDown={onKey} placeholder="Busca secciones, conceptos, puertos, reportes o equipos…"/><kbd>Esc</kbd></label>
      <div className="palette-list" ref={listRef}>
        {results.length ? results.map((entry, index) => {
          const heading = entry.group !== lastGroup; lastGroup = entry.group;
          return <React.Fragment key={`${entry.group}-${entry.title}-${index}`}>
            {heading && <span className="palette-group">{entry.group}</span>}
            <button className={index === cursor ? 'is-cursor' : ''} onMouseEnter={() => setCursor(index)} onClick={() => run(entry)}>
              <Icon name={entry.icon} size={17}/><span><b>{entry.title}</b>{entry.hint && <small>{entry.hint}</small>}</span><Icon name="arrow-right" size={14}/>
            </button>
          </React.Fragment>;
        }) : <p className="palette-empty">Sin resultados para “{query}”.</p>}
      </div>
      <footer><span><kbd>↑</kbd><kbd>↓</kbd> moverse</span><span><kbd>Enter</kbd> abrir</span><span><kbd>Esc</kbd> cerrar</span></footer>
    </div>
  </div>;
}

/** Entradas del buscador que salen de la guía: conceptos, estados, tipos y opciones. */
export function guideEntries(openGuide) {
  const entry = (group, title, hint, section, icon = 'book') => ({ group, title, hint, icon, run: () => openGuide(section) });
  return [
    ...PROFILES.map(item => entry('Guía · Perfiles', `Perfil ${item.title}`, item.what, 'perfiles', item.icon)),
    ...Object.entries(PORT_STATES).map(([state, item]) => entry('Guía · Estados', `Puerto ${item.label.toLowerCase()} (${state})`, item.text, 'estados', 'help')),
    ...Object.values(SCAN_TYPES).map(item => entry('Guía · Tipos de escaneo', `${item.name} ${item.flag}`, item.text, 'tipos', 'scan')),
    ...OPTION_HELP.map(item => entry('Guía · Opciones', `${item.name} ${item.flag}`, item.text, 'opciones', 'sliders')),
    ...GLOSSARY.map(item => entry('Guía · Glosario', item.term, item.text, 'glosario')),
  ];
}

export function CommandPreview({ options, target }) {
  const [open, setOpen] = useState(false);
  const parts = useMemo(() => explainCommand(options, target), [options, target]);
  return <div className={`command-preview ${open ? 'is-open' : ''}`}>
    <div className="command-preview-head">
      <span className="panel-kicker">COMANDO QUE SE VA A EJECUTAR</span>
      <button type="button" onClick={() => setOpen(value => !value)} aria-expanded={open}><Icon name="help" size={14}/>{open ? 'Ocultar explicación' : '¿Qué hace cada parte?'}</button>
    </div>
    <div className="command-chips">{parts.map((part, index) => <code key={`${part.flag}-${index}`} title={part.text} className={index === 0 ? 'is-bin' : index === parts.length - 1 ? 'is-target' : ''}>{part.flag}</code>)}</div>
    {open && <dl className="command-explain">{parts.map((part, index) => <div key={`${part.flag}-${index}`}><dt><code>{part.flag}</code></dt><dd>{part.text}</dd></div>)}</dl>}
    {needsAdmin(options) && <p className="command-note"><Icon name="shield" size={14}/> Esta combinación usa paquetes "raw": en Windows necesita Npcap y puede pedir ejecutar TrabaMap como administrador.</p>}
  </div>;
}

export function GuideView({ section, onPickProfile, go }) {
  const pageRef = useRef(null);
  const [active, setActive] = useState(section || GUIDE_SECTIONS[0].id);
  const jump = id => { setActive(id); pageRef.current?.querySelector(`#guia-${id}`)?.scrollIntoView({ behavior: 'smooth', block: 'start' }); };
  useEffect(() => { if (section) jump(section.split(':')[0]); }, [section]);
  return <main className="page guide-page" ref={pageRef}>
    <header className="page-head"><div><span className="panel-kicker">APRENDER</span><h1>Guía de TrabaMap</h1><p>Qué hace cada botón, qué significa cada resultado y hasta dónde llega un escaneo de red.</p></div>
      <div className="page-actions"><button className="btn-primary" onClick={() => go('scan')}><Icon name="scan" size={16}/><span>Ir al escáner</span></button></div></header>
    <nav className="pill-tabs guide-tabs" aria-label="Secciones de la guía">{GUIDE_SECTIONS.map(item => <button key={item.id} className={active === item.id ? 'is-active' : ''} onClick={() => jump(item.id)}>{item.title}</button>)}</nav>

    <section className="panel guide-section" id="guia-como-funciona"><h2>Cómo funciona</h2>
      <p className="guide-lead">TrabaMap no inventa datos: le pide a <b>Nmap</b>, el escáner de red más usado del mundo, que revise un equipo, y luego traduce su respuesta a español claro.</p>
      <ol className="guide-steps">
        <li><span>1</span><div><b>Eliges un objetivo</b><p>Una IP (192.168.1.20), un nombre de equipo o un rango completo (192.168.1.0/24). TrabaMap detecta solo tu IP, tu router y tu rango.</p></div></li>
        <li><span>2</span><div><b>Nmap envía sondas</b><p>Toca cada puerto del objetivo y anota quién contesta. Con detección de servicios, además pregunta qué programa atiende.</p></div></li>
        <li><span>3</span><div><b>TrabaMap lo explica</b><p>Cada puerto abierto aparece con para qué sirve, un nivel de riesgo orientativo y una recomendación concreta.</p></div></li>
        <li><span>4</span><div><b>Se guarda en tu equipo</b><p>El reporte queda en el historial (JSON, XML original de Nmap y Excel). Nada se envía a Internet.</p></div></li>
      </ol>
      <div className="guide-map">
        <article><Icon name="scan" size={18}/><b>Escáner</b><p>Revisa los puertos de un equipo o varios y lee el resultado explicado.</p></article>
        <article><Icon name="network" size={18}/><b>Dispositivos</b><p>Lista y mapa de todo lo que responde en tu red local, con ficha por equipo.</p></article>
        <article><Icon name="history" size={18}/><b>Historial</b><p>Reportes guardados y qué puertos cambiaron respecto al escaneo anterior.</p></article>
        <article><Icon name="activity" size={18}/><b>Actividad</b><p>Registro de cada escaneo iniciado, terminado, cancelado o con error.</p></article>
      </div>
    </section>

    <section className="panel guide-section" id="guia-perfiles"><h2>Perfiles de escaneo</h2><p className="guide-lead">Un perfil es una combinación de opciones ya preparada. Pulsa uno para cargarlo en el escáner.</p>
      <div className="guide-cards">{PROFILES.map(profile => <article key={profile.id}>
        <header><span className="tile-icon"><Icon name={profile.icon} size={18}/></span><b>{profile.title}</b><em>{profile.time}</em></header>
        <p>{profile.what}</p><p className="guide-when"><b>Úsalo:</b> {profile.when}</p>
        <code>nmap {profile.flags}</code>
        <footer>{profile.admin ? <span className="tag tag-warn">Requiere Npcap / administrador</span> : <span className="tag tag-ok">Sin permisos especiales</span>}<button onClick={() => onPickProfile(profile.id)}>Usar perfil <Icon name="arrow-right" size={13}/></button></footer>
      </article>)}</div>
    </section>

    <section className="panel guide-section" id="guia-estados"><h2>Estados de un puerto</h2><p className="guide-lead">Nmap clasifica cada puerto según la respuesta que recibe.</p>
      <div className="guide-rows">{Object.entries(PORT_STATES).map(([state, item]) => <div key={state}><span className={`port-state state-${item.tone}`}>{state}</span><b>{item.label}</b><p>{item.text}</p></div>)}</div>
    </section>

    <section className="panel guide-section" id="guia-riesgo"><h2>Niveles de riesgo</h2><p className="guide-lead">La valoración es orientativa: un puerto abierto no demuestra una vulnerabilidad, solo indica dónde mirar primero.</p>
      <div className="guide-rows">{RISKS.map(risk => <div key={risk.id}><span className={`risk-tag ${risk.tone}`}><i/>{risk.id}</span><b/><p>{risk.text}</p></div>)}</div>
    </section>

    <section className="panel guide-section" id="guia-tipos"><h2>Tipos de escaneo</h2><p className="guide-lead">Están en “Opciones avanzadas”. Si dudas, deja TCP Connect: funciona siempre.</p>
      <div className="guide-rows">{Object.entries(SCAN_TYPES).map(([id, item]) => <div key={id}><code>{item.flag}</code><b>{item.name}{item.admin && <span className="tag tag-warn">admin</span>}</b><p>{item.text}</p></div>)}</div>
    </section>

    <section className="panel guide-section" id="guia-opciones"><h2>Opciones de Nmap</h2>
      <div className="guide-rows">{OPTION_HELP.map(item => <div key={item.flag}><code>{item.flag}</code><b>{item.name}</b><p>{item.text}</p></div>)}</div>
    </section>

    <section className="panel guide-section" id="guia-glosario"><h2>Glosario</h2>
      <div className="guide-glossary">{GLOSSARY.map(item => <div key={item.term}><b>{item.term}</b><p>{item.text}</p></div>)}</div>
    </section>

    <section className="panel guide-section" id="guia-limites"><h2>Límites y uso responsable</h2>
      <ul className="guide-list">
        <li><Icon name="shield-check" size={16}/><span><b>Escanea solo equipos propios o con autorización.</b> Escanear redes ajenas puede ser ilegal y los scripts NSE envían peticiones reales.</span></li>
        <li><Icon name="info" size={16}/><span>Un equipo que no responde no está necesariamente apagado: puede dormir, filtrar las sondas o estar aislado por el Wi-Fi.</span></li>
        <li><Icon name="info" size={16}/><span><b>Identificación de dispositivos:</b> tras descubrir la red, TrabaMap pregunta a cada equipo qué anuncia de sí mismo (mDNS/Bonjour y UPnP), revisa unos pocos “puertos firma” y mira el TTL del ping. Un televisor o una impresora suelen decir su marca y modelo; cada conclusión muestra su evidencia y su nivel de confianza.</span></li>
        <li><Icon name="info" size={16}/><span>Los celulares modernos usan una MAC privada y casi no anuncian nada: muchas veces solo se puede decir “teléfono o tableta” con confianza baja. El modelo exacto de un Android solo se lee con ADB autorizado; el de un iPhone, con un servidor MDM.</span></li>
        <li><Icon name="info" size={16}/><span>Nmap no puede leer RAM, usuario ni componentes de otro equipo. Eso solo se muestra de tu propio PC o de un Android ya autorizado por ADB.</span></li>
        <li><Icon name="lock" size={16}/><span>Todo se guarda localmente en la carpeta de datos de la aplicación; no hay nube.</span></li>
      </ul>
      <p className="guide-links"><a href="https://nmap.org/man/es/index.html" target="_blank" rel="noreferrer">Manual de Nmap en español</a><a href="https://nmap.org/book/man.html" target="_blank" rel="noreferrer">Referencia vigente (inglés)</a><a href="https://nmap.org/download.html" target="_blank" rel="noreferrer">Descargar Nmap y Npcap</a></p>
    </section>
  </main>;
}
