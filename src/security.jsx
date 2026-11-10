import React, { useEffect, useState } from 'react';
import { Icon } from './icons.jsx';

const DEFAULT_SETTINGS = { privateOnly: true, confirmIntrusive: true, maxHosts: 1024, allowInsaneTiming: false };
const HOST_LIMITS = [[256, '256 · una red doméstica (/24)'], [1024, '1.024 · una oficina (/22)'], [4096, '4.096 · un edificio (/20)'], [65536, '65.536 · una red grande (/16)']];

function Switch({ checked, onChange, label, hint, safe }) {
  return <label className="setting-row">
    <span className="setting-copy"><b>{label}</b><small>{hint}</small></span>
    {checked === safe ? <span className="tag tag-ok">Recomendado</span> : <span className="tag tag-warn">Menos seguro</span>}
    <input type="checkbox" checked={checked} onChange={event => onChange(event.target.checked)}/>
    <span className="switch" aria-hidden="true"><i/></span>
  </label>;
}

export function SecurityView({ api, system, onChanged, openLogs }) {
  const [settings, setSettings] = useState(system?.security || DEFAULT_SETTINGS);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState('');
  useEffect(() => { api.settings?.().then(value => value && setSettings(value)).catch(() => {}); }, []);
  const update = async patch => {
    const next = { ...settings, ...patch };
    setSettings(next); setError('');
    try {
      const stored = await api.saveSettings?.(next);
      if (stored) setSettings(stored);
      setSaved(true); setTimeout(() => setSaved(false), 1600);
      onChanged?.();
    } catch (saveError) { setError(saveError.message || 'No se pudo guardar la configuración.'); }
  };
  const dhcp = system?.dhcp_listener;
  const rules = system?.policy || [];
  return <main className="page security-page">
    <header className="page-head"><div><span className="panel-kicker">SISTEMA</span><h1>Seguridad</h1><p>Lo que TrabaMap nunca hace, lo que te pide confirmar y los límites que tú decides.</p></div>
      <div className="page-actions">{saved && <span className="tag tag-ok saved-tag"><Icon name="check" size={13}/> Guardado</span>}<button className="btn-ghost" onClick={openLogs}><Icon name="activity" size={15}/><span>Ver registro de auditoría</span></button></div></header>
    {error && <div className="inline-error"><Icon name="alert" size={15}/><span>{error}</span></div>}

    <section className="panel security-block"><header><span className="tile-icon"><Icon name="lock" size={18}/></span><div><h2>Reglas fijas</h2><p>Están dentro del motor y no se pueden apagar, ni desde la ventana ni escribiendo parámetros.</p></div></header>
      <ul className="rule-list">{rules.length ? rules.map(rule => <li key={rule}><Icon name="shield-check" size={16}/><span>{rule}</span></li>) : <li><Icon name="info" size={16}/><span>Las reglas se muestran cuando el motor local está disponible.</span></li>}</ul>
    </section>

    <section className="panel security-block"><header><span className="tile-icon"><Icon name="sliders" size={18}/></span><div><h2>Parámetros que tú controlas</h2><p>Vienen en su valor seguro. Cada cambio queda anotado en el registro.</p></div></header>
      <Switch checked={settings.privateOnly} safe={true} onChange={value => update({ privateOnly: value })} label="Avisar antes de escanear fuera de la red local" hint="Si el objetivo es una IP pública o un dominio de Internet, TrabaMap se detiene y pide que confirmes que tienes autorización."/>
      <Switch checked={settings.confirmIntrusive} safe={true} onChange={value => update({ confirmIntrusive: value })} label="Confirmar los escaneos intrusivos" hint="Vulnerabilidades, accesos sin contraseña, malware, rutas web y modo -A piden confirmación antes de salir."/>
      <Switch checked={settings.allowInsaneTiming} safe={false} onChange={value => update({ allowInsaneTiming: value })} label="Permitir la velocidad máxima (T5)" hint="T5 puede saturar una red doméstica y perder resultados. Con esto apagado, el tope es T4."/>
      <label className="setting-row"><span className="setting-copy"><b>Tamaño máximo de un escaneo</b><small>Un rango más grande que este se rechaza: evita lanzar por error un barrido enorme.</small></span>
        <select value={settings.maxHosts} onChange={event => update({ maxHosts: Number(event.target.value) })}>{HOST_LIMITS.map(([value, label]) => <option key={value} value={value}>{label}</option>)}{!HOST_LIMITS.some(([value]) => value === settings.maxHosts) && <option value={settings.maxHosts}>{settings.maxHosts}</option>}</select></label>
    </section>

    <section className="panel security-block"><header><span className="tile-icon"><Icon name="wifi" size={18}/></span><div><h2>Escucha DHCP</h2><p>Sirve para saber con certeza si un celular es Android o iPhone. Solo escucha; nunca responde ni reparte direcciones.</p></div>
      <span className={`tag ${dhcp?.active ? 'tag-ok' : 'tag-warn'}`}>{dhcp?.active ? `Activa · ${dhcp.seen} equipos vistos` : 'Inactiva'}</span></header>
      <ul className="rule-list">
        <li><Icon name="info" size={16}/><span>Cuando un equipo entra al Wi-Fi se presenta al router. Android dice “android-dhcp-14” (con su versión), Windows “MSFT 5.0”, y iPhone/Mac piden una lista de datos que solo usa Apple.</span></li>
        <li><Icon name="info" size={16}/><span><b>Para identificar un celular al instante:</b> apaga y enciende su Wi-Fi con TrabaMap abierto y vuelve a buscar dispositivos.</span></li>
        {!dhcp?.active && <li><Icon name="alert" size={16}/><span>{dhcp?.reason || 'La escucha no está disponible en este equipo.'} Si Windows pregunta si TrabaMap puede comunicarse en redes privadas, hay que permitirlo.</span></li>}
      </ul>
    </section>

    <section className="panel security-block"><header><span className="tile-icon"><Icon name="file" size={18}/></span><div><h2>Privacidad y registro</h2><p>Todo se queda en este computador.</p></div></header>
      <ul className="rule-list">
        <li><Icon name="lock" size={16}/><span>Los reportes, el historial y el registro se guardan en la carpeta de datos de la aplicación. TrabaMap no envía nada a Internet.</span></li>
        <li><Icon name="activity" size={16}/><span>Cada escaneo anota fecha, usuario de Windows, objetivo, opciones exactas y las advertencias que confirmaste. También se anotan los escaneos bloqueados.</span></li>
        <li><Icon name="shield-check" size={16}/><span>La ventana no tiene acceso directo al sistema: pide cada acción al proceso principal, que valida los datos antes de ejecutar nada.</span></li>
      </ul>
    </section>
  </main>;
}

export function ConfirmDialog({ request, onAnswer }) {
  const [accepted, setAccepted] = useState(false);
  useEffect(() => {
    setAccepted(false);
    if (!request) return undefined;
    const onKey = event => { if (event.key === 'Escape') onAnswer(false); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [request]);
  if (!request) return null;
  return <div className="device-detail-scrim confirm-scrim" onMouseDown={() => onAnswer(false)}>
    <section className="confirm-dialog" role="alertdialog" aria-modal="true" aria-labelledby="confirm-title" onMouseDown={event => event.stopPropagation()}>
      <header><span className="confirm-icon"><Icon name="shield-alert" size={22}/></span><div><span className="panel-kicker">PARÁMETROS DE SEGURIDAD</span><h2 id="confirm-title">Antes de continuar</h2></div></header>
      <p className="confirm-target">Objetivo: <code>{request.target}</code></p>
      <ul>{request.needs.map(item => <li key={item.code}><b>{item.title}</b><span>{item.text}</span></li>)}</ul>
      <label className="check-option confirm-check"><input type="checkbox" checked={accepted} onChange={event => setAccepted(event.target.checked)}/><span className="check-box">{accepted && <Icon name="check" size={11}/>}</span><span>El equipo es mío o tengo autorización de su dueño. Entiendo que esta confirmación queda en el registro.</span></label>
      <footer><button className="btn-ghost" onClick={() => onAnswer(false)}>Cancelar</button><button className="btn-primary" disabled={!accepted} onClick={() => onAnswer(true)}><Icon name="play" size={13}/><span>Continuar con el escaneo</span></button></footer>
    </section>
  </div>;
}
