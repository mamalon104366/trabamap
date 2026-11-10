import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import '@fontsource/manrope/400.css';
import '@fontsource/manrope/500.css';
import '@fontsource/manrope/600.css';
import '@fontsource/manrope/700.css';
import '@fontsource/ibm-plex-mono/400.css';
import '@fontsource/ibm-plex-mono/500.css';
import { Icon, LogoTile } from './icons.jsx';
import { Sidebar, CommandPalette, CommandPreview, GuideView, guideEntries, VIEW_LABELS } from './shell.jsx';
import { PORT_STATES } from './knowledge.js';
import { identify, isPrivateMac, CONFIDENCE_LABELS, SIGNATURE_PORTS, OS_FAMILIES } from './identify.js';
import { CatalogView, TargetPicker, PRESETS, CATEGORIES } from './catalog.jsx';
import { SecurityView, ConfirmDialog } from './security.jsx';
import './styles.css';

const defaults = {
  profile: 'quick', scan_type: 'connect', ports: 'common', custom_ports: '22,80,443',
  skip_discovery: false, service_detection: true, version_intensity: 5,
  os_detection: false, os_guess: false, os_scan_limit: false, scripts: 'off', traceroute: false, timing: 3,
  aggressive: false, ipv6: false, dns_mode: 'off', custom_args: '', idle_zombie: '', sequential_ports: false,
};
const unavailableApi = async () => { throw new Error('Abre TrabaMap como aplicación de escritorio para acceder a Nmap.'); };
const api = window.trabamap || {
  scan: unavailableApi, cancelScan: async () => {}, reports: async () => [], logs: async () => [],
  report: unavailableApi, openReport: unavailableApi, exportExcel: unavailableApi,
  system: async () => ({ hostname: 'Equipo local', local_ip: '127.0.0.1', interfaces: [], nmap: 'No disponible' }),
  onScanProgress: () => () => {}, identify: async () => ({ devices: {}, sources: {} }),
};
// Electron antepone un texto técnico a los errores que vienen del proceso principal; al usuario no le sirve.
const cleanMessage = error => String(error?.message || '').replace(/^Error invoking remote method '[^']+':\s*(Error:\s*)?/, '');
const riskClass = { 'Muy alto': 'critical', Alto: 'high', Medio: 'medium', Bajo: 'low', Informativo: 'info' };
const fmtDate = value => {
  if (!value) return 'Fecha no disponible';
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : date.toLocaleString('es-CO', { dateStyle: 'medium', timeStyle: 'short' });
};
const respondingCount = scan => scan?.runstats?.up ?? scan?.hosts?.filter(host => host.status === 'up').length ?? 0;
function isLocalHost(address, target, system) {
  const local = new Set([
    system?.local_ip, system?.hostname, 'localhost', '127.0.0.1', '::1',
    ...(system?.interfaces || []).map(item => item.address),
    ...(system?.local_inventory?.local_addresses || []).map(item => item.address),
  ].filter(Boolean).map(value => String(value).trim().toLowerCase()));
  const candidate = String(address || '').trim().toLowerCase().replace(/^::ffff:/, '');
  if (candidate && local.has(candidate)) return true;
  return String(target || '').trim().toLowerCase().split(/[\s,]+/).some(value => local.has(value));
}
function formatBytes(value) {
  const size = Number(value);
  if (!Number.isFinite(size) || size <= 0) return 'No disponible';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let amount = size, unit = 0;
  while (amount >= 1024 && unit < units.length - 1) { amount /= 1024; unit++; }
  return `${amount.toLocaleString('es-CO', { maximumFractionDigits: amount < 10 ? 1 : 0 })} ${units[unit]}`;
}

function App() {
  const [view, setView] = useState('scan');
  const [booting, setBooting] = useState(true);
  const [rawSystem, setSystem] = useState(null);
  const [target, setTarget] = useState('');
  const [options, setOptions] = useState(defaults);
  const [advanced, setAdvanced] = useState(false);
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState({ message: 'Preparando Nmap…', percent: null });
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);
  const [networkScan, setNetworkScan] = useState(null);
  const [identifyingAddress, setIdentifyingAddress] = useState('');
  const [networkBusy, setNetworkBusy] = useState(false);
  const [selectedHost, setSelectedHost] = useState(0);
  const [reports, setReports] = useState([]);
  const [logs, setLogs] = useState([]);
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState('Todos');
  const [copied, setCopied] = useState(false);
  const [detail, setDetail] = useState(null);
  const [rawOpen, setRawOpen] = useState(false);
  const [exportNotice, setExportNotice] = useState(null);
  const [collapsed, setCollapsed] = useState(() => { try { return localStorage.getItem('trabamap.sidebar') === 'collapsed'; } catch { return false; } });
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [guideSection, setGuideSection] = useState('');
  const [theme, setTheme] = useState(() => { try { return localStorage.getItem('trabamap.theme') === 'light' ? 'light' : 'dark'; } catch { return 'dark'; } });
  const [confirmRequest, setConfirmRequest] = useState(null);
  const toggleTheme = useCallback(() => setTheme(value => value === 'light' ? 'dark' : 'light'), []);
  useEffect(() => { document.documentElement.dataset.theme = theme; try { localStorage.setItem('trabamap.theme', theme); } catch { /* almacenamiento no disponible */ } }, [theme]);
  const askConfirm = (needs, targetValue) => new Promise(resolve => setConfirmRequest({ needs, target: targetValue, resolve }));
  const [ifaceAddress, setIfaceAddress] = useState('');
  const interfaces = rawSystem?.interfaces || [];
  const iface = interfaces.find(item => item.address === ifaceAddress) || interfaces[0];
  // La interfaz elegida define la IP local y el rango que usan todas las vistas.
  const system = useMemo(() => rawSystem && iface ? { ...rawSystem, local_ip: iface.address, network_cidr: iface.network || iface.cidr || rawSystem.network_cidr } : rawSystem, [rawSystem, iface]);
  const go = useCallback(next => { setView(next); setDetail(null); }, []);
  const openGuide = useCallback(section => { setGuideSection(`${section}:${Date.now()}`); setView('guide'); setDetail(null); }, []);
  useEffect(() => { try { localStorage.setItem('trabamap.sidebar', collapsed ? 'collapsed' : 'open'); } catch { /* almacenamiento no disponible */ } }, [collapsed]);
  useEffect(() => {
    const onKey = event => { if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') { event.preventDefault(); setPaletteOpen(value => !value); } };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const refresh = async () => {
    const [reportResult, logResult, systemResult] = await Promise.allSettled([api.reports(), api.logs(), api.system()]);
    if (reportResult.status === 'fulfilled') setReports(reportResult.value || []);
    if (logResult.status === 'fulfilled') setLogs(logResult.value || []);
    if (systemResult.status === 'fulfilled') setSystem(systemResult.value);
  };

  useEffect(() => {
    let alive = true;
    let bootTimer;
    const start = Date.now();
    const unsubscribe = api.onScanProgress?.(event => setProgress({ message: event.message || 'Nmap está analizando…', percent: event.percent ?? null }));
    Promise.allSettled([api.system(), api.reports(), api.logs()]).then(values => {
      if (!alive) return;
      if (values[0].status === 'fulfilled') {
        setSystem(values[0].value);
        setTarget(values[0].value.local_ip || '127.0.0.1');
      } else {
        setError(values[0].reason?.message || 'No se pudo consultar la configuración local.');
      }
      if (values[1].status === 'fulfilled') setReports(values[1].value || []);
      if (values[2].status === 'fulfilled') setLogs(values[2].value || []);
      bootTimer = setTimeout(() => alive && setBooting(false), Math.max(0, 620 - (Date.now() - start)));
    });
    return () => { alive = false; clearTimeout(bootTimer); unsubscribe?.(); };
  }, []);

  const availableHosts = (result?.hosts || []).map((item, index) => ({ item, index })).filter(entry => entry.item.status === 'up');
  const activeHost = availableHosts.find(entry => entry.index === selectedHost) || availableHosts[0];
  const host = activeHost?.item || null;
  const ports = host?.ports || [];
  const visiblePorts = useMemo(() => ports.filter(port =>
    (filter === 'Todos' || port.risk === filter) &&
    `${port.port} ${port.protocol} ${port.name} ${port.service} ${port.description} ${port.state}`.toLowerCase().includes(query.toLowerCase())
  ), [ports, filter, query]);

  const setOption = (key, value) => setOptions(previous => ({ ...previous, [key]: value, profile: 'custom' }));
  const pickProfile = profile => {
    const profiles = {
      quick: { ...defaults, profile: 'quick' },
      complete: { ...defaults, profile: 'complete', scan_type: 'syn', ports: 'all', os_detection: true },
      intense: { ...defaults, profile: 'intense', scan_type: 'syn', service_detection: false, aggressive: true, timing: 4 },
      discovery: { ...defaults, profile: 'discovery', scan_type: 'ping', service_detection: false, scripts: 'off' },
    };
    setOptions(profiles[profile]);
  };
  const executeScan = async ({ targetValue = target, optionsValue = options, destination = 'ports' } = {}) => {
    if (busy) return;
    setError(''); setBusy(true); setProgress({ message: 'Iniciando Nmap…', percent: null });
    if (destination === 'ports') setResult(null);
    if (destination === 'network') setNetworkScan(null);
    if (destination === 'identify') setIdentifyingAddress(targetValue);
    setNetworkBusy(destination !== 'ports');
    setDetail(null);
    if (destination === 'network' || destination === 'identify') setView('network');
    else setView('scan');
    try {
      // Parámetros de seguridad: el proceso principal decide si hay que bloquear o pedir confirmación.
      const verdict = await api.policyCheck?.({ target: targetValue.trim(), options: optionsValue });
      if (verdict?.blocked?.length) throw new Error(verdict.blocked.join(' '));
      let acknowledged = [];
      if (verdict?.needs?.length) {
        if (!await askConfirm(verdict.needs, targetValue.trim())) throw new Error('Escaneo no iniciado: no se confirmó la advertencia de seguridad.');
        acknowledged = verdict.needs.map(item => item.code);
      }
      const scanned = await api.scan({ target: targetValue.trim(), options: optionsValue, acknowledged });
      if (destination === 'network') setNetworkScan({ ...scanned, hosts: (scanned.hosts || []).map(item => isLocalHost(item.address, targetValue, system) ? { ...item, local_inventory: system?.local_inventory } : item), captured_at: new Date().toISOString() });
      else if (destination === 'identify') {
        const identified = scanned.hosts?.[0];
        if (identified) setNetworkScan(previous => previous ? { ...previous, hosts: previous.hosts.map(item => item.address === identified.address ? { ...item, ...identified, status: item.status || identified.status, mac: item.mac || identified.mac, mac_vendor: item.mac_vendor || identified.mac_vendor, local_inventory: isLocalHost(identified.address, targetValue, system) ? system?.local_inventory : item.local_inventory, identification_scan: { nmap_version: scanned.nmap_version, command: scanned.nmap_command || scanned.command, elapsed_seconds: scanned.elapsed_seconds, options: optionsValue, captured_at: new Date().toISOString() } } : item) } : previous);
      } else {
        setResult(scanned); setSelectedHost(0); setQuery(''); setFilter('Todos');
      }
      await refresh();
      return scanned;
    } catch (scanError) {
      setError(cleanMessage(scanError) || 'Nmap no pudo completar el escaneo.');
      await refresh();
      return null;
    } finally { setBusy(false); setIdentifyingAddress(''); setNetworkBusy(false); }
  };
  const scan = event => { event?.preventDefault(); if (busy) return api.cancelScan(); return executeScan(); };
  const discoverNetwork = () => {
    const network = iface?.network || iface?.cidr || system?.network_cidr;
    if (!network) { setView('network'); setError('No se pudo calcular el rango de esta interfaz. Revisa la conexión de red.'); return; }
    setTarget(network);
    return discoverAndIdentify({ targetValue: network, destination: 'network', optionsValue: { ...defaults, profile: 'discovery', scan_type: 'ping', ports: 'top100', service_detection: false, os_detection: false, scripts: 'off', timing: 3, dns_mode: 'resolve' } });
  };
  // Fase 2 del descubrimiento: preguntar a cada equipo qué anuncia de sí mismo y revisar sus puertos firma.
  const discoverAndIdentify = async request => {
    const discovered = await executeScan(request);
    const addresses = (discovered?.hosts || []).filter(item => item.status === 'up').map(item => item.address);
    if (!discovered || !addresses.length) return;
    setBusy(true); setNetworkBusy(true);
    setProgress({ message: 'Identificando dispositivos: mDNS, UPnP y puertos firma…', percent: null });
    try {
      const [passive, signature] = await Promise.allSettled([
        api.identify?.({ localAddress: system?.local_ip, addresses, macs: Object.fromEntries((discovered.hosts || []).filter(item => item.mac).map(item => [item.address, item.mac])) }),
        api.scan({ target: addresses.length <= 110 ? addresses.join(' ') : request.targetValue, options: { ...defaults, profile: 'signature', ephemeral: true, scan_type: 'connect', ports: 'custom', custom_ports: SIGNATURE_PORTS.join(','), skip_discovery: true, service_detection: true, version_intensity: 2, os_detection: true, os_guess: true, timing: 4, dns_mode: 'off', custom_args: '--host-timeout 60s --max-retries 1 --max-os-tries 1 --script nbstat' } }),
      ]);
      const evidence = passive.status === 'fulfilled' ? passive.value?.devices || {} : {};
      const scanned = signature.status === 'fulfilled' ? signature.value?.hosts || [] : [];
      setNetworkScan(previous => {
        if (!previous) return previous;
        const known = new Set(previous.hosts.map(item => item.address));
        // Equipos que no respondieron a Nmap pero sí se anunciaron por mDNS/UPnP.
        const extra = Object.keys(evidence).filter(address => !known.has(address) && (evidence[address].mdns || evidence[address].upnp))
          .map(address => ({ address, addresses: [], mac: '', mac_vendor: '', hostnames: [], hostname: '', status: 'up', ports: [], other_ports: [], os_matches: [], scripts: [], trace: [], found_by: 'anuncio' }));
        const hosts = [...previous.hosts, ...extra].map(item => {
          const found = scanned.find(candidate => candidate.address === item.address);
          const netbios = (found?.scripts || []).find(script => script.id === 'nbstat')?.output?.match(/NetBIOS name:\s*([^,\s]+)/i)?.[1];
          return { ...item, evidence: evidence[item.address] || item.evidence || null, ports: found?.ports?.length ? found.ports : item.ports, scripts: found?.scripts?.length ? found.scripts : item.scripts, os_matches: found?.os_matches?.length ? found.os_matches : item.os_matches, hostname: item.hostname || (netbios && !/unknown/i.test(netbios) ? netbios : ''), signature_scan: Boolean(found) || item.signature_scan };
        });
        return { ...previous, hosts, runstats: previous.runstats ? { ...previous.runstats, up: hosts.filter(item => item.status === 'up').length } : previous.runstats, identified_at: new Date().toISOString(), identify_sources: passive.status === 'fulfilled' ? passive.value?.sources : null };
      });
      await refresh();
    } finally { setBusy(false); setNetworkBusy(false); }
  };
  const identifyDevice = device => executeScan({ targetValue: device.address, destination: 'identify', optionsValue: { ...defaults, profile: 'identify', scan_type: 'connect', ports: 'all', service_detection: true, version_intensity: 7, os_detection: true, os_guess: true, scripts: 'off', timing: 3, dns_mode: 'resolve', custom_args: '--script smb-os-discovery' } });
  const openSavedReport = async name => {
    try { const saved = await api.report(name); setDetail(saved); setView('history'); }
    catch (openError) { setError(cleanMessage(openError) || 'No se pudo abrir este reporte.'); }
  };
  const exportReport = async report => {
    if (!report) return;
    try {
      const adbDevices = system?.adb_inventory?.devices || [];
      const evidence = {
        ...report,
        adb_inventory: system?.adb_inventory || null,
        hosts: (report.hosts || []).map(item => {
          const local = isLocalHost(item.address, report.target, system);
          const adb = adbDevices.find(device => device.authorized && device.address && device.address === item.address);
          const identity = describeDevice(item, local ? system?.local_inventory : item.local_inventory, item.address === system?.gateway, adb);
          return { ...item, ...(local ? { local_inventory: item.local_inventory || system?.local_inventory } : {}), ...(adb ? { adb_inventory: adb } : {}), identity: { type: identity.deviceType, brand: identity.vendor, model: identity.model, os: identity.os, confidence: CONFIDENCE_LABELS[identity.confidence], reasons: identity.reasons.map(reason => reason.text) } };
        }),
      };
      const exported = await api.exportExcel(evidence);
      setExportNotice(exported);
      setTimeout(() => setExportNotice(current => current?.name === exported.name ? null : current), 9000);
    } catch (exportError) { setError(cleanMessage(exportError) || 'No se pudo crear el archivo Excel.'); }
  };
  const copy = async value => {
    if (!value) return;
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch { setError('Windows no permitió copiar el texto al portapapeles.'); }
  };
  const hasNmap = Boolean(system?.nmap && !['No disponible', 'No detectado'].includes(system.nmap)) && system?.engine !== 'integrado';
  // Sin Nmap sigue habiendo motor: el integrado descubre equipos y revisa puertos TCP.
  const isReady = hasNmap || system?.engine === 'integrado';

  const deviceChoices = useMemo(() => (networkScan?.hosts || []).filter(item => item.status === 'up').map(item => {
    const info = describeDevice(item, isLocalHost(item.address, networkScan?.target, system) ? system?.local_inventory : item.local_inventory, item.address === system?.gateway);
    return { address: item.address, label: `${info.name || item.hostname || item.address} · ${info.os} · ${item.address}` };
  }), [networkScan, system]);
  const runPreset = (preset, presetOptions) => {
    const value = target.trim() || system?.local_ip || '';
    setOptions(presetOptions);
    return executeScan({ targetValue: value, optionsValue: presetOptions, destination: ['ping', 'list'].includes(presetOptions.scan_type) && !preset.noTarget ? 'network' : 'ports' });
  };
  const pickProfileAndGo = profile => { if (profile === 'discovery') return discoverNetwork(); pickProfile(profile); go('scan'); };
  const paletteEntries = useMemo(() => [
    ...Object.entries(VIEW_LABELS).map(([id, label]) => ({ group: 'Ir a', title: label, icon: id === 'scan' ? 'scan' : id === 'network' ? 'network' : id === 'catalog' ? 'list' : id === 'security' ? 'shield-check' : id === 'history' ? 'history' : id === 'logs' ? 'activity' : 'book', pinned: true, run: () => go(id) })),
    ...PRESETS.map(preset => ({ group: `Catálogo · ${CATEGORIES.find(item => item.id === preset.cat).title}`, title: preset.title, hint: preset.what, icon: 'play', run: () => go('catalog') })),
    { group: 'Acciones', title: 'Buscar dispositivos en mi red', hint: system?.network_cidr || '', icon: 'wifi', pinned: true, run: () => discoverNetwork() },
    { group: 'Acciones', title: 'Escanear este equipo', hint: system?.local_ip || '', icon: 'zap', pinned: true, run: () => { setTarget(system?.local_ip || '127.0.0.1'); go('scan'); } },
    ...(networkScan?.hosts || []).filter(item => item.status === 'up').map(item => ({ group: 'Dispositivos', title: item.hostname || item.address, hint: [item.address, item.mac_vendor].filter(Boolean).join(' · '), icon: 'server', run: () => { setTarget(item.address); go('scan'); } })),
    ...reports.map(report => ({ group: 'Reportes', title: report.target, hint: `${fmtDate(report.date)} · ${report.summary?.open_ports ?? 0} puertos abiertos`, icon: 'file', run: () => openSavedReport(report.name) })),
    ...guideEntries(openGuide),
  ], [system, networkScan, reports, go, openGuide]);

  return <div className={`app-shell ${collapsed ? 'sidebar-collapsed' : ''} ${booting ? 'is-booting' : ''}`}>
    {booting && <div className="boot-screen" aria-label="Iniciando TrabaMap">
      <LogoTile size={72} className="boot-mark"/>
      <strong>TrabaMap</strong>
      <span>Preparando el motor local</span>
      <div className="boot-progress"><i/></div>
    </div>}

    <Sidebar view={view} go={go} collapsed={collapsed} setCollapsed={setCollapsed}
      counts={{ network: respondingCount(networkScan), history: reports.length, logs: logs.length }}
      system={system} isReady={isReady} hasNmap={hasNmap} theme={theme} toggleTheme={toggleTheme} busy={busy} onDiscover={discoverNetwork} onSearch={() => setPaletteOpen(true)} onRefresh={refresh}
      interfaces={interfaces} activeAddress={iface?.address || ''} setActiveAddress={setIfaceAddress}/>

    <div className="app-content">
      <header className="topbar">
        <div className="breadcrumbs"><span>TrabaMap</span><Icon name="chevron-right" size={13}/><b>{VIEW_LABELS[view]}</b>{detail && view === 'history' && <><Icon name="chevron-right" size={13}/><span>Reporte</span></>}</div>
        <div className="top-controls">
          {busy && <button className="busy-pill" onClick={() => go(networkBusy ? 'network' : 'scan')} title="Ver el escaneo en curso"><Icon name="loader" size={13} className="spin"/>Escaneando{progress.percent != null ? ` · ${progress.percent}%` : '…'}</button>}
          <span className="privacy-pill" title="Los datos no salen de este equipo"><Icon name="lock" size={13}/>Solo local</span>
          <button className="icon-button theme-toggle" onClick={toggleTheme} title={theme === 'light' ? 'Cambiar a tema oscuro' : 'Cambiar a tema claro'} aria-label={theme === 'light' ? 'Cambiar a tema oscuro' : 'Cambiar a tema claro'}><Icon name={theme === 'light' ? 'moon' : 'sun'} size={17}/></button>
          <button className="icon-button" onClick={() => openGuide('como-funciona')} title="Abrir la guía" aria-label="Abrir la guía"><Icon name="help" size={17}/></button>
          <button className="icon-button" onClick={refresh} title="Actualizar datos" aria-label="Actualizar datos"><Icon name="refresh" size={16}/></button>
        </div>
      </header>

      {view === 'scan' && <ScanView {...{
        target, setTarget, system, options, setOption, pickProfile, advanced, setAdvanced,
        busy, progress, scan, result, availableHosts, activeHost, host, ports, visiblePorts, query, setQuery, filter,
        setFilter, error, setError, selectedHost, setSelectedHost, copied, copy, reports,
        logs, rawOpen, setRawOpen, setView: go, openSavedReport, isReady, discoverNetwork,
        exportReport, openGuide, interfaces, setIfaceAddress, deviceChoices,
      }}/ >}
      {view === 'network' && <NetworkView {...{ system, networkScan, busy, progress, error, setError, discoverNetwork, identifyDevice, identifyingAddress, isReady, cancelScan: api.cancelScan, exportReport, scanDevice: address => { setTarget(address); go('scan'); } }}/ >}
      {view === 'history' && <HistoryView {...{ reports, detail, setDetail, openSavedReport, setView: go, exportReport }}/ >}
      {view === 'logs' && <LogsView logs={logs} refresh={refresh}/ >}
      {view === 'catalog' && <CatalogView {...{ target, setTarget, system, devices: deviceChoices, busy, isReady, runPreset, openGuide }}/ >}
      {view === 'security' && <SecurityView api={api} system={system} onChanged={refresh} openLogs={() => go('logs')}/ >}
      {view === 'guide' && <GuideView section={guideSection} onPickProfile={pickProfileAndGo} go={go}/ >}
    </div>

    {exportNotice && <div className="toast" role="status"><span className="toast-icon"><Icon name="check" size={15}/></span><span>Excel guardado<b>{exportNotice.name}</b></span><button onClick={() => api.openReport(exportNotice.name)}><Icon name="external" size={14}/> Abrir</button><button className="toast-close" aria-label="Cerrar aviso" onClick={() => setExportNotice(null)}><Icon name="x" size={14}/></button></div>}
    <ConfirmDialog request={confirmRequest} onAnswer={answer => { confirmRequest?.resolve(answer); setConfirmRequest(null); }}/>
    <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} entries={paletteEntries}/>
  </div>;
}

function ScanView(props) {
  const {
    target, setTarget, system, options, setOption, pickProfile, advanced, setAdvanced,
    busy, progress, scan, result, availableHosts, activeHost, host, ports, visiblePorts, query, setQuery, filter,
    setFilter, error, setError, selectedHost, setSelectedHost, copied, copy, reports,
    logs, rawOpen, setRawOpen, setView, openSavedReport, isReady, discoverNetwork, exportReport, openGuide, interfaces, setIfaceAddress, deviceChoices,
  } = props;
  const noPortScan = ['ping', 'list'].includes(result?.scan_type);
  const openPorts = ports.filter(port => port.state === 'open');
  const isLocalScan = Boolean(host && isLocalHost(host.address, result?.target || target, system));
  const localListenerFor = port => isLocalScan ? system?.local_inventory?.tcp_listeners?.find(listener => Number(listener.port) === Number(port.port)) : null;
  const canDetectServices = ['connect', 'syn', 'udp', 'both', 'sctp'].includes(options.scan_type);
  const canDetectOs = ['connect', 'syn', 'both'].includes(options.scan_type);
  const targetAvailable = Boolean(target.trim() || /(?:^|\s)(?:-iL|-iR|--inputfile|--randomtargets)(?:\s|$)/i.test(options.custom_args || ''));
  const scriptResults = [...(result?.network_scripts || []), ...(host?.scripts || []), ...ports.flatMap(port => (port.scripts || []).map(script => ({ ...script, port: port.port, protocol: port.protocol })))];
  const setScanType = scanType => {
    setOption('scan_type', scanType);
    if (['ping', 'list'].includes(scanType)) {
      setOption('service_detection', false);
      setOption('os_detection', false);
      setOption('scripts', 'off');
      setOption('aggressive', false);
    }
    if (!['connect', 'syn', 'udp', 'both', 'sctp'].includes(scanType) && options.aggressive) setOption('aggressive', false);
  };

  return <main className="page scan-page">
    <header className="page-head"><div><span className="panel-kicker">GENERAL</span><h1>Escáner</h1><p>Revisa qué puertos y servicios expone un equipo y lee cada resultado explicado.</p></div>
      <div className="page-actions"><button className="btn-ghost" onClick={() => setView('catalog')}><Icon name="list" size={15}/><span>Catálogo de {PRESETS.length} escaneos</span></button><button className="btn-ghost" onClick={() => openGuide('perfiles')}><Icon name="book" size={15}/><span>¿Qué perfil elijo?</span></button></div></header>
    <div className="scan-columns">
      <div className="primary-column">
        <form className="scan-panel" onSubmit={scan}>
          <div className="scan-panel-head">
            <div><span className="section-index"><Icon name="scan" size={17}/></span><div><span className="panel-kicker">NUEVO ESCANEO</span><h2>Elige un objetivo</h2></div></div>
            <button type="button" className={`advanced-toggle ${advanced ? 'open' : ''}`} onClick={() => setAdvanced(value => !value)}><Icon name="sliders" size={15}/>{advanced ? 'Cerrar opciones' : 'Opciones avanzadas'}<Icon name="chevron-down" size={13}/></button>
          </div>
          <label className="target-label" htmlFor="target">IP, nombre de equipo o rango de red</label>
          <div className="target-row">
            <div className="target-field"><Icon name="globe" size={18}/><input id="target" value={target} onChange={event => setTarget(event.target.value)} placeholder="192.168.1.1, una red o un hostname"/>
              <button type="button" className="autofill" onClick={() => setTarget(system?.local_ip || '127.0.0.1')} title="Usar la IP detectada en este equipo">MI EQUIPO <b>{system?.local_ip || '…'}</b></button>
            </div>
            <button className={`launch-button ${busy ? 'cancel' : ''}`} type="submit" disabled={!busy && (!targetAvailable || !isReady)}>
              {busy ? <><Icon name="stop" size={13}/> Cancelar</> : <><Icon name="play" size={14}/> Escanear <Icon name="arrow-up-right" size={15}/></>}
            </button>
          </div>

          <TargetPicker target={target} setTarget={setTarget} system={system} devices={deviceChoices}/>

          <div className="profile-row"><span className="profile-label">PERFIL</span>
            <ProfileButton active={options.profile === 'quick'} onClick={() => pickProfile('quick')} icon="zap" title="Rápido" subtitle="1000 puertos"/>
            <ProfileButton active={options.profile === 'complete'} onClick={() => pickProfile('complete')} icon="network" title="Completo" subtitle="Todos los TCP"/>
            <ProfileButton active={options.profile === 'intense'} onClick={() => pickProfile('intense')} icon="shield-alert" title="Intensivo" subtitle="Detección ampliada"/>
            <ProfileButton active={false} onClick={discoverNetwork} icon="wifi" title="Descubrir" subtitle="Equipos de la red"/>
          </div>

          <CommandPreview options={options} target={target}/>

          {advanced && <div className="advanced-panel">
            <div className="advanced-grid">
              <label className="option-control"><span>TIPO DE ESCANEO</span><select value={options.scan_type} onChange={event => setScanType(event.target.value)}><option value="connect">TCP Connect · -sT</option><option value="syn">TCP SYN · -sS</option><option value="udp">UDP · -sU</option><option value="both">TCP SYN + UDP</option><option value="ack">TCP ACK · -sA</option><option value="window">TCP Window · -sW</option><option value="maimon">TCP Maimon · -sM</option><option value="fin">TCP FIN · -sF</option><option value="null">TCP Null · -sN</option><option value="xmas">TCP Xmas · -sX</option><option value="sctp">SCTP INIT · -sY</option><option value="sctp_cookie">SCTP Cookie · -sZ</option><option value="ip_proto">Protocolos IP · -sO</option><option value="ping">Descubrimiento · -sn</option><option value="list">Lista sin sondeo · -sL</option></select></label>
              <label className="option-control"><span>PUERTOS</span><select value={options.ports} onChange={event => setOption('ports', event.target.value)}><option value="fast">Rápido · -F</option><option value="top100">100 comunes</option><option value="common">1000 comunes</option><option value="top">Cantidad personalizada</option><option value="all">Todos · 1–65535</option><option value="custom">Lista o rangos</option></select></label>
              {options.ports === 'top' && <label className="option-control"><span>CANTIDAD · --top-ports</span><input type="number" min="1" max="65535" value={options.top_port_count || 1000} onChange={event => setOption('top_port_count', Number(event.target.value))}/></label>}
              {options.ports === 'custom' && <label className="option-control"><span>RANGO / PROTOCOLO</span><input value={options.custom_ports} onChange={event => setOption('custom_ports', event.target.value)} placeholder="22,80,443 · U:53,T:1-100"/></label>}
              <label className="option-control range-control"><span>VELOCIDAD · T{options.timing}</span><input type="range" min="0" max="5" value={options.timing} onChange={event => setOption('timing', Number(event.target.value))}/></label>
              {options.service_detection && canDetectServices && !options.aggressive && <label className="option-control range-control"><span>INTENSIDAD DE VERSIÓN · {options.version_intensity}</span><input type="range" min="0" max="9" value={options.version_intensity} onChange={event => setOption('version_intensity', Number(event.target.value))}/></label>}
              {!options.aggressive && <label className="option-control"><span>SCRIPTS NSE</span><select value={options.scripts} onChange={event => setOption('scripts', event.target.value)}><option value="off">Desactivados</option><option value="safe">Seguros · safe</option><option value="default">Por defecto · -sC</option><option value="discovery">Descubrimiento</option><option value="vuln">Comprobaciones vuln</option></select></label>}
              <label className="option-control"><span>RESOLUCIÓN DNS</span><select value={options.dns_mode} onChange={event => setOption('dns_mode', event.target.value)}><option value="off">Desactivada · -n</option><option value="resolve">Normal</option><option value="force">Forzar · -R</option></select></label>
            </div>
            <div className="check-row">
              <CheckOption checked={options.service_detection} onChange={value => setOption('service_detection', value)} label="Servicios y versiones" disabled={!canDetectServices || options.aggressive}/>
              <CheckOption checked={options.os_detection} onChange={value => setOption('os_detection', value)} label="Sistema operativo" disabled={!canDetectOs || options.aggressive}/>
              <CheckOption checked={options.skip_discovery} onChange={value => setOption('skip_discovery', value)} label="Omitir ping previo · -Pn"/>
              <CheckOption checked={options.traceroute} onChange={value => setOption('traceroute', value)} label="Trazar ruta"/>
              <CheckOption checked={options.ipv6} onChange={value => setOption('ipv6', value)} label="Forzar IPv6 · -6"/>
              <CheckOption checked={options.sequential_ports} onChange={value => setOption('sequential_ports', value)} label="Puertos en orden · -r" disabled={['ping', 'list', 'ip_proto'].includes(options.scan_type)}/>
              <CheckOption checked={options.os_guess} onChange={value => setOption('os_guess', value)} label="Intentar más huellas SO · --osscan-guess" disabled={!options.os_detection}/>
              <CheckOption checked={options.os_scan_limit} onChange={value => setOption('os_scan_limit', value)} label="Limitar detección SO · --osscan-limit" disabled={!options.os_detection}/>
              <CheckOption checked={options.aggressive} onChange={value => value ? setOptionsForAggressive() : setOption('aggressive', false)} label="Modo avanzado · -A"/>
            </div>
            <label className="option-control raw-options"><span>OTROS PARÁMETROS NMAP</span><input value={options.custom_args} onChange={event => setOption('custom_args', event.target.value)} placeholder="--exclude 192.168.1.5 --scan-delay 100ms --script-args ..."/><small>Se pasan a Nmap como argumentos, sin shell. El objetivo y los archivos XML siguen controlados por TrabaMap. Admite opciones de objetivos, sondeos, NSE, tiempos, interfaz, origen, evasión y diagnóstico.</small></label>
            <div className="manual-links"><a href="https://nmap.org/man/es/index.html" target="_blank" rel="noreferrer">Manual en español</a><span>·</span><a href="https://nmap.org/book/man.html" target="_blank" rel="noreferrer">Referencia vigente de Nmap</a></div>
            {(['syn', 'udp', 'both', 'ack', 'fin', 'null', 'xmas', 'sctp'].includes(options.scan_type) || options.os_detection || options.aggressive) && <div className="inline-note"><Icon name="shield" size={14}/> Este tipo de escaneo puede necesitar permisos de administrador o Npcap en Windows.</div>}
            {options.scripts === 'vuln' && <div className="inline-note"><Icon name="alert" size={14}/> Los scripts NSE pueden enviar solicitudes específicas. Úsalos solo en equipos autorizados.</div>}
          </div>}

          <div className="scan-footer"><span><Icon name="shield-check" size={14}/> Escanea solo equipos propios o con autorización.</span><span>{options.scan_type === 'udp' ? 'UDP puede tardar varios minutos' : options.ports === 'all' ? '65.535 puertos · puede tardar' : 'Tiempo habitual: 1–3 min'}</span></div>
          {error && <div className="inline-error"><Icon name="alert" size={15}/><span>{error}</span><button type="button" onClick={() => setError('')} aria-label="Cerrar error"><Icon name="x" size={14}/></button></div>}
          {busy && <div className="live-progress"><div className="progress-head"><span><Icon name="loader" size={14} className="spin"/>{progress.message}</span>{progress.percent != null && <b>{progress.percent}%</b>}</div><div className="progress-track"><i style={progress.percent != null ? { width: `${progress.percent}%` } : undefined}/></div></div>}
        </form>

        <section className="results-panel">
          <div className="results-top"><div><span className="panel-kicker">LECTURA DEL ESCANEO</span><h2>{result ? 'Puertos encontrados' : 'Resultados'} <span>{result ? openPorts.length : '—'}</span></h2></div>
            <div className="results-actions">{availableHosts.length > 1 && <select className="host-select" value={activeHost?.index ?? 0} onChange={event => setSelectedHost(Number(event.target.value))}>{availableHosts.map(({ item, index }) => <option key={item.address} value={index}>{item.hostname || item.address}</option>)}</select>}
              {result && <button className="command-toggle" onClick={() => setRawOpen(value => !value)}><Icon name="code" size={14}/>{rawOpen ? 'Cerrar comando' : 'Comando Nmap'}</button>}
            </div>
          </div>
          {result ? <>
            <div className="result-summary"><span className="target-result"><Icon name="server" size={15}/><b>{host?.hostname || host?.address || result.target}</b><small>{host?.address || result.target}</small><button onClick={() => copy(host?.address || result.target)} title="Copiar dirección">{copied ? <Icon name="check" size={13}/> : <Icon name="copy" size={13}/>}</button></span>
              <span className="result-stats"><b>{result.summary?.open_ports || 0}</b> abiertos <i/><b>{result.summary?.filtered_ports || 0}</b> filtrados <i/><b>{result.summary?.closed_ports || 0}</b> cerrados</span>
            </div>
            {result.fallback_note && <div className="inline-note"><Icon name="info" size={14}/> {result.fallback_note}</div>}
            {rawOpen && <div className="raw-command"><code>nmap {result.nmap_command || result.command}</code><button onClick={() => copy(result.nmap_command || result.command)} aria-label="Copiar comando">{copied ? <Icon name="check" size={13}/> : <Icon name="copy" size={13}/>}</button></div>}
            <div className="table-controls"><label className="table-search"><Icon name="search" size={14}/><input value={query} onChange={event => setQuery(event.target.value)} placeholder="Buscar puerto o servicio"/></label>
              <div className="risk-filters">{['Todos', 'Muy alto', 'Alto', 'Medio', 'Bajo'].map(value => <button className={filter === value ? 'on' : ''} key={value} onClick={() => setFilter(value)}>{value}</button>)}</div>
              <div className="export-group"><button className="export-button" onClick={() => exportReport({ ...result, hosts: (result.hosts || []).map(item => isLocalHost(item.address, result.target, system) ? { ...item, local_inventory: system?.local_inventory } : item) })}><Icon name="table" size={14}/> Excel</button><button className="export-button" onClick={() => result.report_file && api.openReport(result.report_file)}><Icon name="download" size={14}/> JSON</button><button className="export-button" onClick={() => result.raw_xml_file && api.openReport(result.raw_xml_file)}><Icon name="code" size={14}/> XML</button></div>
            </div>
            <div className="port-table-scroll"><table className="port-table"><thead><tr><th>PUERTO</th><th>SERVICIO</th><th>ESTADO</th><th>QUÉ ES Y RIESGO</th><th>QUÉ HACER</th></tr></thead><tbody>
              {visiblePorts.map(port => <tr key={`${port.port}/${port.protocol}`}><td className="port-number">{port.port}<small>/{port.protocol}</small></td>
                <td><div className="detected-service"><span><Icon name={port.service === 'https' || port.service === 'http' ? 'globe' : port.port === 3306 || port.port === 5432 ? 'hard-drive' : 'terminal'} size={15}/></span><div><b>{port.name || port.service}</b><small>{[port.product, port.version].filter(Boolean).join(' ') || port.service}</small>{port.application && <small title={port.application_source}>Aplicación: {isLocalScan && port.state === 'open' ? localListenerFor(port)?.application || port.application : port.application}</small>}{isLocalScan && port.state === 'open' && <small className="local-process-match">Proceso local · PID {localListenerFor(port)?.pid || 'no identificado'}</small>}</div></div></td>
                <td><span className={`port-state state-${PORT_STATES[port.state]?.tone || 'filtered'}`} title={PORT_STATES[port.state]?.text}>{PORT_STATES[port.state]?.label || port.state}</span><small className="reason">{port.reason}</small></td>
                <td><div className="risk-cell"><span className={`risk-tag ${riskClass[port.risk] || 'info'}`}><i/>{port.risk}</span><span>{port.description}</span></div></td>
                <td className="recommendation">{port.recommendation}</td></tr>)}
            </tbody></table>{visiblePorts.length === 0 && <div className="no-results"><Icon name="shield-check" size={20}/><b>{ports.length ? 'Sin coincidencias' : noPortScan ? 'Este escaneo no revisó puertos' : 'Nmap no reportó puertos'}</b><span>{ports.length ? 'Prueba otro filtro o búsqueda.' : noPortScan ? 'Fue un descubrimiento de equipos. Elige el perfil Rápido para ver puertos.' : host ? 'El equipo respondió sin servicios abiertos.' : 'Ningún equipo respondió. Puede estar apagado o filtrando las sondas; prueba “Omitir ping previo”.'}</span></div>}</div>
            {isLocalScan && system?.local_inventory ? <LocalMachineDetails inventory={system.local_inventory} nmapPorts={openPorts}/> : host?.os_matches?.length > 0 && <div className="os-match"><span><Icon name="hard-drive" size={15}/> SISTEMA PROBABLE · NMAP</span><b>{host.os_matches[0].name}</b><small>{host.os_matches[0].accuracy}% de coincidencia estimada</small></div>}
            {scriptResults.length > 0 && <details className="data-disclosure" open={ports.length === 0}><summary><span>RESULTADOS NSE · {scriptResults.length}</span><Icon name="chevron-down" size={14}/></summary><div className="script-result-list">{scriptResults.map((script, index) => <article key={`${script.id}-${script.port || 'host'}-${index}`}><b>{script.id}{script.port ? ` · ${script.port}/${script.protocol}` : ''}</b><p>{script.output}</p>{script.details?.length > 0 && <ul>{script.details.map((line, lineIndex) => <li key={lineIndex}>{line}</li>)}</ul>}</article>)}</div></details>}
            {host?.trace?.length > 0 && <details className="data-disclosure"><summary><span>RUTA DE RED · {host.trace.length} SALTOS</span><Icon name="chevron-down" size={14}/></summary><div className="trace-list">{host.trace.map((hop, index) => <span key={`${hop.address}-${index}`}><b>{String(hop.ttl).padStart(2, '0')}</b>{hop.hostname || hop.address || '*'}{hop.rtt && <small>{hop.rtt} ms</small>}</span>)}</div></details>}
          </> : <div className="results-empty"><LogoTile size={56}/><div><b>Tu lectura aparecerá aquí</b><span>Verás cada puerto abierto con su estado, para qué sirve, el nivel de riesgo y qué hacer con él.</span></div><button type="button" className="btn-ghost" onClick={() => openGuide('estados')}><Icon name="help" size={15}/><span>Cómo leer los resultados</span></button></div>}
        </section>
      </div>

      <aside className="inspector-column">
        <section className="machine-card"><div className="side-card-head"><span>ESTE EQUIPO</span><span className="local-state"><i/> LOCAL</span></div>
          <div className="machine-identity"><div className="machine-icon"><Icon name="server" size={21}/></div><div><b>{system?.hostname || 'Equipo local'}</b><span>Dispositivo de origen</span></div></div>
          <div className="machine-address"><span>DIRECCIÓN IP</span><b>{system?.local_ip || 'Detectando…'}</b></div>
          <div className="local-network-details"><div><span>ROUTER</span><b>{system?.gateway || 'No detectado'}</b></div><div><span>RANGO LOCAL</span><b>{(system?.interfaces?.find(item => item.address === system.local_ip) || system?.interfaces?.[0])?.network || system?.network_cidr || 'No disponible'}</b></div></div>
          <div className="machine-foot"><span>INTERFAZ</span>{system?.interfaces?.length > 1 ? <select aria-label="Interfaz de red" value={system.local_ip} onChange={event => { setIfaceAddress(event.target.value); setTarget(event.target.value); }}>{interfaces.map(item => <option key={item.address} value={item.address}>{item.name} · {item.address}</option>)}</select> : <b>{system?.interfaces?.[0]?.name || 'Red principal'}</b>}</div>
          <button className="local-scan-button" onClick={discoverNetwork} disabled={busy || !isReady}><Icon name="network" size={16}/>{busy ? 'Escaneo en curso' : 'Buscar equipos de esta red'}</button>
        </section>

        <section className="engine-card"><div className="engine-top"><span className="engine-symbol"><Icon name="scan" size={18}/></span><span className={isReady ? 'engine-connected' : 'engine-disconnected'}><i/>{isReady ? 'LISTO' : 'SIN MOTOR'}</span></div><h3>Motor de análisis</h3><p>{system?.engine === 'integrado' ? 'Motor integrado · equipos y puertos TCP' : isReady ? `Nmap ${system.nmap}` : 'El motor local no respondió.'}</p>{!isReady && <small className="engine-help">Revisa la instalación de Nmap y reinicia la app.</small>}<div className="engine-capabilities"><span>TCP</span><span>UDP</span><span>NSE</span><span>XML</span></div></section>

        <section className="activity-card"><div className="activity-heading"><div><span className="panel-kicker">REGISTRO LOCAL</span><h3>Actividad reciente</h3></div><button onClick={() => setView('logs')} aria-label="Abrir toda la actividad"><Icon name="arrow-right" size={15}/></button></div>
          {logs.slice(0, 3).length ? logs.slice(0, 3).map((log, index) => <LogSnippet key={`${log.time}-${index}`} log={log}/>) : <div className="no-activity"><Icon name="activity" size={17}/><span>Los eventos aparecerán aquí al escanear.</span></div>}
        </section>
        {result && <section className="result-note"><span className="note-mark"><Icon name="shield-check" size={17}/></span><div><b>Escaneo terminado</b><span>{result.summary?.hosts || 0} equipos · {result.nmap_version || system?.nmap}</span></div></section>}
        {reports.length > 0 && <button className="last-report" onClick={() => openSavedReport(reports[0].name)}><Icon name="file" size={14}/><span>Último reporte guardado</span><Icon name="chevron-right" size={14}/></button>}
      </aside>
    </div>
  </main>;

  function setOptionsForAggressive() {
    props.setOption('aggressive', true);
    props.setOption('service_detection', true);
    props.setOption('os_detection', true);
    props.setOption('scripts', 'default');
    props.setOption('traceroute', true);
  }
}

function LocalMachineDetails({ inventory, nmapPorts = [] }) {
  const processors = inventory.cpu || [];
  const listeners = inventory.tcp_listeners || [];
  const nmapOpen = new Set(nmapPorts.filter(port => port.protocol === 'tcp').map(port => Number(port.port)));
  const cpuNames = [...new Set(processors.map(cpu => cpu.name).filter(Boolean))];
  const cores = processors.reduce((total, cpu) => total + (Number(cpu.cores) || 0), 0);
  const logical = processors.reduce((total, cpu) => total + (Number(cpu.logical_processors) || 0), 0);
  const board = (inventory.motherboard || []).map(item => [item.manufacturer, item.product].filter(Boolean).join(' ')).filter(Boolean).join(' · ');
  const gpuNames = [...new Set((inventory.gpu || []).map(gpu => gpu.name).filter(Boolean))];
  const storage = (inventory.storage || []).map(disk => `${disk.model || 'Disco'} · ${formatBytes(disk.size_bytes)}`);
  return <section className="local-machine-details">
    <header><div><span className="panel-kicker">INVENTARIO DE ESTE EQUIPO</span><h3>Datos leídos localmente</h3></div><span>NO ES UNA CONJETURA NMAP</span></header>
    <div className="local-machine-grid">
      <div><span>Sistema y versión</span><b>{inventory.os_name || 'No disponible'}</b><small>{[inventory.os_version && `versión ${inventory.os_version}`, inventory.os_build && `compilación ${inventory.os_build}`, inventory.architecture].filter(Boolean).join(' · ')}</small></div>
      <div><span>Usuario de esta sesión</span><b>{inventory.user_name || 'No disponible'}</b><small>{inventory.source || 'Consulta local'}</small></div>
      {(inventory.computer_manufacturer || inventory.computer_model) && <div><span>Fabricante y modelo</span><b>{[inventory.computer_manufacturer, inventory.computer_model].filter(Boolean).join(' · ')}</b></div>}
      <div><span>Memoria RAM</span><b>{formatBytes(inventory.ram_total_bytes)}</b><small>{formatBytes(inventory.ram_free_bytes)} disponible ahora</small></div>
      <div><span>Procesador</span><b>{cpuNames.join(' / ') || 'No disponible'}</b><small>{[cores && `${cores} núcleos`, logical && `${logical} procesadores lógicos`].filter(Boolean).join(' · ') || 'Núcleos sin datos'}</small></div>
      {board && <div><span>Placa base</span><b>{board}</b></div>}
      {gpuNames.length > 0 && <div><span>Gráficos</span><b>{gpuNames.join(' · ')}</b></div>}
      {(inventory.memory_modules || []).length > 0 && <div><span>Módulos RAM</span><b>{inventory.memory_modules.map((item, index) => `${formatBytes(item.capacity_bytes)}${item.speed_mhz ? ` · ${item.speed_mhz} MHz` : ''}${item.manufacturer ? ` · ${item.manufacturer}` : ` · módulo ${index + 1}`}`).join(' / ')}</b></div>}
      {storage.length > 0 && <div><span>Almacenamiento físico</span><b>{storage.join(' / ')}</b></div>}
    </div>
    <div className="local-listener-block"><div className="local-listener-heading"><b>Puertos TCP en escucha y aplicación</b><span>{listeners.length} entradas</span></div>
      {listeners.length ? <div className="local-listener-table"><div className="local-listener-row local-listener-labels"><span>PUERTO</span><span>DIRECCIÓN LOCAL</span><span>APLICACIÓN</span><span>PID</span><span>ESCANEO</span></div>{listeners.map((listener, index) => <div className="local-listener-row" key={`${listener.port}-${listener.address}-${listener.pid}-${index}`}><code>{listener.port}/TCP</code><code>{listener.address || '—'}</code><b>{listener.application || 'Proceso no identificado'}</b><code>{listener.pid || '—'}</code><span className={nmapOpen.has(Number(listener.port)) ? 'listener-confirmed' : ''}>{nmapOpen.has(Number(listener.port)) ? 'Abierto en Nmap' : 'En escucha local'}</span></div>)}</div> : <p className="device-detail-empty">{inventory.platform === 'win32' ? 'Windows no devolvió puertos TCP en escucha para esta sesión.' : 'El mapeo de procesos y puertos locales está disponible ahora en Windows; este sistema solo compartió los datos básicos de la máquina.'}</p>}
      <small>Un proceso puede escuchar solo en localhost o quedar bloqueado por el firewall; por eso no siempre aparece abierto desde la IP de red.</small>
    </div>
  </section>;
}

/** Identificación completa: la base clásica más lo que el equipo anuncia (mDNS, UPnP, puertos firma, TTL). */
function describeDevice(host, localInventory = null, isGateway = false, adb = null) {
  const hasOpenPort = (host.ports || []).some(port => port.state === 'open');
  const reliable = hasOpenPort || !host.os_matches?.length ? host : { ...host, os_matches: [], os_unreliable: true };
  return identify(baseDescribe(reliable, localInventory, isGateway), reliable, { isGateway, adb });
}

function baseDescribe(host, localInventory = null, isGateway = false) {
  if (localInventory) {
    const kind = localInventory.platform === 'win32' ? 'windows' : localInventory.platform === 'darwin' ? 'apple' : 'linux';
    return { os: localInventory.os_name || 'Sistema local', kind, deviceType: 'este equipo', accuracy: null, vendor: localInventory.computer_manufacturer || 'Equipo local', isLocal: true };
  }
  const match = host.os_matches?.[0];
  const osClass = match?.classes?.[0];
  const evidence = [match?.name, osClass?.family, osClass?.vendor, host.hostname, ...(host.hostnames || []), host.mac_vendor,
    ...(host.ports || []).filter(port => port.state === 'open').flatMap(port => [port.service, port.product, port.version])].filter(Boolean).join(' ').toLowerCase();
  let os = match?.name || [osClass?.vendor, osClass?.family, osClass?.generation].filter(Boolean).join(' ');
  let kind = 'device';
  let deviceType = osClass?.type || '';
  const set = (label, glyph, type) => { os = label; kind = glyph; if (type) deviceType = type; };
  if (/iphone|ipad|apple ios|\bios \d|watchos/.test(evidence)) set('iOS', 'apple', 'teléfono o tableta');
  else if (/android/.test(evidence)) set('Android', 'android', 'teléfono o tableta');
  else if (/windows/.test(evidence)) {
    const version = evidence.match(/windows\s*(7|8\.1|8|10|11|xp|vista|server\s*\d{4})/i)?.[1];
    set(`Windows${version ? ` ${version.replace(/server\s*/i, 'Server ')}` : ''}`, 'windows', 'computadora o servidor');
  } else if (/ubuntu/.test(evidence)) set('Ubuntu Linux', 'ubuntu', 'computadora o servidor');
  else if (/debian/.test(evidence)) set('Debian Linux', 'debian', 'computadora o servidor');
  else if (/arch linux|archlinux/.test(evidence)) set('Arch Linux', 'arch', 'computadora o servidor');
  else if (/fedora/.test(evidence)) set('Fedora Linux', 'linux', 'computadora o servidor');
  else if (/linux|openwrt/.test(evidence)) set('Linux', /router|openwrt/.test(evidence) ? 'router' : 'linux', /router|openwrt/.test(evidence) ? 'router' : 'computadora o servidor');
  else if (/macos|mac os|darwin|os x/.test(evidence)) set('macOS', 'apple', 'computadora');
  else if (/apple/.test((host.mac_vendor || '').toLowerCase())) { kind = 'apple'; deviceType = 'equipo Apple (tipo sin confirmar)'; }
  else if (/router|gateway|access point|access-point|mikrotik|ubiquiti|tp-link|netgear|cisco/.test(evidence) || /router|wap|firewall|switch/.test(deviceType)) { os = match?.name || 'Sistema sin determinar'; kind = 'router'; deviceType = 'router'; }
  else if (/printer|impresora/.test(evidence) || /printer/.test(deviceType)) { kind = 'device'; deviceType = 'impresora'; }
  else if (/motorola|samsung electronics|xiaomi|redmi|poco|huawei|honor|oneplus|oppo|vivo|realme|tecno|infinix|itel|transsion|google pixel/.test(`${(host.mac_vendor || '').toLowerCase()} ${evidence}`)) { kind = 'phone'; deviceType = 'posible teléfono o tableta'; }
  else if (/phone|mobile|tablet|iphone|ipad|android/.test(deviceType)) { kind = 'phone'; deviceType = 'teléfono o tableta'; }
  else if (/computer|workstation|general purpose|desktop|server/.test(deviceType) || /microsoft|intel|dell|hp|lenovo|asus|acer|apple/.test(host.mac_vendor?.toLowerCase() || '')) { kind = kind === 'device' ? 'computer' : kind; deviceType = deviceType || 'computadora'; }
  const accuracy = match?.accuracy ?? osClass?.accuracy;
  if (isGateway && !['windows', 'apple', 'android'].includes(kind)) { kind = 'router'; deviceType = 'router de la red'; }
  return { os: os || 'SO sin determinar', kind, deviceType: deviceType || 'dispositivo de red', accuracy: Number.isFinite(Number(accuracy)) ? Number(accuracy) : null, vendor: host.mac_vendor || osClass?.vendor || '' };
}

function DeviceGlyph({ kind = 'device' }) {
  const marks = {
    windows: <><path d="M3 5.2 10.7 4v7H3zM12.3 3.8 21 2.5V11h-8.7zM3 12.8h7.7v7L3 18.6zM12.3 12.8H21v8.7l-8.7-1.3z" fill="currentColor" stroke="none"/></>,
    apple: <path d="M16.9 12.7c0-2 1.6-3 1.7-3.1a4.1 4.1 0 0 0-3.2-1.7c-1.4-.1-2.7.8-3.4.8s-1.8-.8-2.9-.8a4.4 4.4 0 0 0-3.7 2.2c-1.6 2.7-.4 6.7 1.1 8.9.7 1.1 1.5 2.3 2.6 2.2 1-.1 1.4-.7 2.7-.7s1.7.7 2.8.7c1.1 0 1.8-1.1 2.5-2.2.8-1.2 1.1-2.4 1.1-2.5-.1 0-2.3-.9-2.3-3.8ZM14.7 6.5a4 4 0 0 0 1-2.9 4.2 4.2 0 0 0-2.7 1.4 3.8 3.8 0 0 0-1 2.8 3.5 3.5 0 0 0 2.7-1.3Z" fill="currentColor" stroke="none"/>,
    android: <><path d="M7 8 5.3 5.5M17 8l1.7-2.5M5 10h14v7a2 2 0 0 1-2 2h-1v2h-2v-2h-4v2H8v-2H7a2 2 0 0 1-2-2z"/><path d="M4 11v6M20 11v6M9 12v.01M15 12v.01"/></>,
    ubuntu: <><circle cx="12" cy="12" r="7.5"/><circle cx="12" cy="4.3" r="1.5" fill="currentColor"/><circle cx="5.3" cy="15.8" r="1.5" fill="currentColor"/><circle cx="18.7" cy="15.8" r="1.5" fill="currentColor"/><path d="m7 7 2 2m8 0 2-2m-9 9-2 2m8-2 2 2"/></>,
    debian: <path d="M14.5 4.5c-3.1-.9-6.2.9-6.5 3.6-.2 1.9 1.2 3.4 3.1 3.2 1.3-.2 2-1.3 1.7-2.3-.3-.9-1.5-1.2-2.1-.5-.5.6-.1 1.5.7 1.5m.3-5.8c4.4-.6 7.4 2.7 6.6 6.6-.7 3.8-4.5 6.2-8 5.1-3.3-1-4.5-4.4-2.9-6.8"/>,
    arch: <><path d="M12 3 3.5 21h4l4.5-9.5L16.5 21h4z"/><path d="m10.3 15.5 1.7-3.7 1.7 3.7z"/></>,
    linux: <><path d="M12 3c-2 0-3 1.8-3 4v2c-1.7 1.2-2.5 3.6-2.5 6.2 0 3.8 2.1 6.3 5.5 6.3s5.5-2.5 5.5-6.3c0-2.6-.8-5-2.5-6.2V7c0-2.2-1-4-3-4Z"/><path d="M9.5 12h.01M14.5 12h.01M10 16c1.2.8 2.8.8 4 0"/></>,
    tv: <><rect x="2.5" y="4" width="19" height="12.5" rx="1.6"/><path d="M8 20.5h8M12 16.5v4"/><path d="m10.3 8.2 4 2.1-4 2.1z" fill="currentColor" stroke="none"/></>,
    printer: <><path d="M7 8V3.5h10V8"/><rect x="3" y="8" width="18" height="9" rx="2"/><path d="M7 14h10v6.5H7zM17.5 11.5h.01"/></>,
    console: <><path d="M7 7.5h10a4.5 4.5 0 0 1 4.4 5.4l-.7 3.4a2.4 2.4 0 0 1-4.2 1l-1.7-2.1H9.2l-1.7 2.1a2.4 2.4 0 0 1-4.2-1l-.7-3.4A4.5 4.5 0 0 1 7 7.5Z"/><path d="M7 10.5v3M5.5 12h3M15.5 11h.01M17.5 13h.01"/></>,
    camera: <><path d="M3 7.5 16 4l1.5 5.5-13 3.5z"/><path d="m17 8 3.5 1.2-.8 3-3.4-.4M7 12.5V17a2 2 0 0 0 2 2h3M3 21v-5"/></>,
    speaker: <><rect x="6" y="2.5" width="12" height="19" rx="3"/><circle cx="12" cy="14.5" r="3"/><path d="M12 7h.01"/></>,
    iot: <><path d="M9 18h6M10 21h4M8.2 14.5a6 6 0 1 1 7.6 0c-.6.6-.8 1.2-.8 2H9c0-.8-.2-1.4-.8-2Z"/></>,
    nas: <><rect x="4" y="3" width="16" height="18" rx="2"/><path d="M4 9h16M4 15h16M8 6h.01M8 12h.01M8 18h.01"/></>,
    router: <><rect x="3" y="8" width="18" height="11" rx="2"/><path d="M7 8V5m10 3V5M7 14h.01M11 14h.01M15 14h.01M19 14h.01M8 17h8"/></>,
    phone: <><rect x="6" y="2.5" width="12" height="19" rx="2.2"/><path d="M10 5h4M11 18.5h2"/></>,
    computer: <><rect x="3" y="3.5" width="18" height="13" rx="1.5"/><path d="M12 16.5v4m-4 0h8"/></>,
    device: <><rect x="3" y="5" width="18" height="14" rx="2"/><path d="M7 9h.01M10 9h7M7 13h10M7 16h5"/></>,
  };
  return <svg className={`device-glyph glyph-${kind}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.45" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{marks[kind] || marks.device}</svg>;
}

function NetworkView({ system, networkScan, busy, progress, error, setError, discoverNetwork, identifyDevice, identifyingAddress, isReady, cancelScan, exportReport, scanDevice }) {
  const [contextMenu, setContextMenu] = useState(null);
  const [mode, setMode] = useState('list');
  const [osFilter, setOsFilter] = useState('all');
  const [detailDevice, setDetailDevice] = useState(null);
  const active = system?.interfaces?.find(item => item.address === system.local_ip) || system?.interfaces?.[0];
  const hosts = (networkScan?.hosts || []).filter(item => item.status === 'up');
  const infoOf = device => describeDevice(device, isLocalHost(device.address, networkScan?.target, system) ? system?.local_inventory : device.local_inventory, device.address === system?.gateway, (system?.adb_inventory?.devices || []).find(item => item.authorized && item.address === device.address));
  const described = hosts.map(device => ({ device, info: infoOf(device) }));
  const identified = described.filter(entry => entry.info.confidence !== 'baja').length;
  const families = OS_FAMILIES.map(family => ({ ...family, count: described.filter(entry => entry.info.osFamily === family.id).length })).filter(family => family.count > 0);
  const activeFilter = families.some(family => family.id === osFilter) ? osFilter : 'all';
  const shown = described.filter(entry => activeFilter === 'all' || entry.info.osFamily === activeFilter).map(entry => entry.device);
  useEffect(() => {
    if (!contextMenu && !detailDevice) return undefined;
    const closeOnEscape = event => { if (event.key === 'Escape') { setContextMenu(null); setDetailDevice(null); } };
    window.addEventListener('keydown', closeOnEscape);
    return () => window.removeEventListener('keydown', closeOnEscape);
  }, [contextMenu, detailDevice]);
  const showDeviceMenu = (x, y, device) => setContextMenu({ x: Math.max(8, Math.min(x, window.innerWidth - 252)), y: Math.max(8, Math.min(y, window.innerHeight - 170)), device });
  const openDeviceMenu = event => { event.preventDefault(); showDeviceMenu(event.clientX, event.clientY, event.currentTarget.dataset.address ? hosts.find(host => host.address === event.currentTarget.dataset.address) : null); };
  const openMenuForDevice = (event, device) => { event.preventDefault(); showDeviceMenu(event.clientX, event.clientY, device); };
  const openDetails = device => { setContextMenu(null); setDetailDevice(device); };
  const startIdentification = device => { setContextMenu(null); identifyDevice(device); };
  return <main className="page network-page">
    <div className="page-head"><div><span className="panel-kicker">INVENTARIO LOCAL</span><h1>Dispositivos</h1><p>Equipos que respondieron al descubrimiento de Nmap en tu red local.</p></div><div className="page-actions">{networkScan && <button className="btn-ghost" onClick={() => exportReport(networkScan)}><Icon name="table" size={15}/><span>Excel de la red</span></button>}<button className="btn-primary" onClick={busy ? cancelScan : discoverNetwork} disabled={!busy && !isReady}><Icon name={busy ? 'stop' : 'wifi'} size={17}/>{busy ? 'Cancelar análisis' : networkScan ? 'Actualizar lista' : 'Buscar dispositivos'}</button></div></div>
    <section className="network-overview">
      <div className="network-info"><span>ESTE EQUIPO</span><b>{system?.hostname || 'Equipo local'}</b><code>{system?.local_ip || 'Detectando IP…'}</code></div>
      <div className="network-info"><span>RANGO LOCAL</span><b>{active?.network || system?.network_cidr || active?.cidr || 'No disponible'}</b><code>{active?.name || 'Interfaz principal'}</code></div>
      <div className="network-info"><span>ROUTER</span><b>{system?.gateway || 'No detectado'}</b><code>Puerta de enlace</code></div>
      <div className="network-count"><b>{networkScan ? hosts.length : '—'}</b><span>equipos que respondieron</span></div>
    </section>
    <AndroidAccessPanel inventory={system?.adb_inventory}/>
    {system?.dhcp_listener && <div className={`dhcp-hint ${system.dhcp_listener.active ? '' : 'is-off'}`}><Icon name="wifi" size={15}/><span>{system.dhcp_listener.active ? <>Escucha DHCP activa · {system.dhcp_listener.seen} equipos vistos. <b>Para saber con certeza si un celular es Android o iPhone, apaga y enciende su Wi-Fi</b> y pulsa “Actualizar lista”.</> : `Escucha DHCP inactiva: ${system.dhcp_listener.reason}`}</span></div>}
    {busy && <div className="network-progress"><Icon name="loader" size={16} className="spin"/><span>{progress.message || 'Nmap está analizando la red…'}</span>{progress.percent != null && <b>{progress.percent}%</b>}<button onClick={cancelScan}>Cancelar</button></div>}
    {error && <div className="inline-error"><Icon name="alert" size={16}/><span>{error}</span><button onClick={() => setError('')} aria-label="Cerrar error"><Icon name="x" size={14}/></button></div>}
    <section className="network-device-panel"><div className="network-device-head"><div><h2>Equipos encontrados</h2><p>{networkScan ? `${networkScan.target} · ${networkScan.nmap_version ? `Nmap ${networkScan.nmap_version}` : 'último análisis'}` : 'Ejecuta un descubrimiento para ver los equipos activos.'}</p></div><div className="network-head-tools"><span className="network-os-total">{identified} de {hosts.length} identificados con confianza</span><div className="pill-tabs" role="tablist" aria-label="Forma de ver los equipos"><button role="tab" aria-selected={mode === 'list'} className={mode === 'list' ? 'is-active' : ''} onClick={() => setMode('list')}><Icon name="list" size={14}/>Lista</button><button role="tab" aria-selected={mode === 'map'} className={mode === 'map' ? 'is-active' : ''} onClick={() => setMode('map')}><Icon name="map" size={14}/>Mapa</button></div></div></div>
      {families.length > 0 && <div className="os-filter" role="group" aria-label="Filtrar por sistema operativo"><span>Sistema</span><button className={activeFilter === 'all' ? 'is-active' : ''} onClick={() => setOsFilter('all')}>Todos<b>{hosts.length}</b></button>{families.map(family => <button key={family.id} className={`os-${family.id} ${activeFilter === family.id ? 'is-active' : ''}`} onClick={() => setOsFilter(family.id)}>{family.label}<b>{family.count}</b></button>)}</div>}
      {hosts.length && mode === 'map' ? <NetworkMap hosts={shown} system={system} onOpen={openDetails} infoFor={device => describeDevice(device, isLocalHost(device.address, networkScan?.target, system) ? system?.local_inventory : device.local_inventory, device.address === system?.gateway)}/> : hosts.length ? <div className="device-list">{shown.map(device => {
        const localInventory = isLocalHost(device.address, networkScan?.target, system) ? system?.local_inventory : device.local_inventory;
        const adbInfo = (system?.adb_inventory?.devices || []).find(item => item.authorized && item.address === device.address);
        const info = describeDevice(device, localInventory, device.address === system?.gateway, adbInfo);
        return <article className="device-row" key={device.address} tabIndex={0} aria-label={`${device.hostname || device.address}, menú contextual para ver detalles`} data-address={device.address} onContextMenu={openDeviceMenu} onDoubleClick={() => openDetails(device)} onKeyDown={event => { if (event.key === 'Enter' && event.target === event.currentTarget) openDetails(device); if (event.key === 'ContextMenu' || (event.shiftKey && event.key === 'F10')) { const rect = event.currentTarget.getBoundingClientRect(); openMenuForDevice({ preventDefault: () => event.preventDefault(), clientX: rect.left + 90, clientY: rect.top + 32 }, device); } }}>
          <span className={`device-icon device-${info.kind}`}><DeviceGlyph kind={info.kind}/></span>
          <div className="device-address"><b>{info.name || device.hostname || device.address}</b><code>{device.address}</code></div>
          <div className="device-os"><span><DeviceGlyph kind={info.kind}/>{info.os}</span><small><i className={`confidence-dot confidence-${info.confidence}`}/>{info.deviceType} · {CONFIDENCE_LABELS[info.confidence].toLowerCase()}</small></div>
          <div className="device-vendor">{info.vendor && <BrandBadge vendor={info.vendor} hostname={`${device.hostname || ''} ${(device.hostnames || []).join(' ')}`}/>}<b>{[info.vendor, info.model].filter(Boolean).join(' · ') || 'Marca y modelo sin anunciar'}</b><small>{info.reasons[0]?.text}</small>{device.mac && <code>{device.mac}{isPrivateMac(device.mac) ? ' · MAC privada' : ''}</code>}</div>
          <button className="row-info-button" onClick={() => openDetails(device)} title="Ver la ficha del equipo" aria-label={`Ver la ficha de ${device.hostname || device.address}`}><Icon name="info" size={16}/></button><button className="identify-button" onClick={() => identifyDevice(device)} disabled={busy} title="Escanea todos los puertos TCP y consulta servicios, versión, SO y SMB si está disponible; puede tardar">{identifyingAddress === device.address ? <><Icon name="loader" size={14} className="spin"/> Analizando</> : device.identification_scan ? 'Actualizar detalles' : device.os_matches?.length ? 'Análisis completo' : 'Escaneo profundo'}</button>
        </article>;
      })}</div> : <div className="network-empty"><span className="network-empty-icon"><Icon name="network" size={23}/></span><b>{networkScan ? 'Nmap no encontró equipos que respondieran' : 'Todavía no hay una lista de equipos'}</b><p>{networkScan ? 'Un equipo puede estar conectado y no responder a estas sondas por su firewall, suspensión o aislamiento Wi-Fi.' : 'TrabaMap detecta automáticamente la IP, el router y el rango de esta interfaz. Pulsa buscar cuando quieras iniciar el escaneo.'}</p>{!networkScan && <button className="network-empty-action" onClick={discoverNetwork} disabled={busy || !isReady}><Icon name="wifi" size={15}/> Buscar en {active?.network || system?.network_cidr || active?.cidr || 'la red local'}</button>}</div>}
    </section>
    <p className="network-footnote"><Icon name="shield-check" size={15}/> El número cuenta dispositivos que respondieron, no personas conectadas. El SO y el tipo se infieren de las huellas que Nmap recibe; el resultado puede quedar sin identificar. En Windows, la detección avanzada puede requerir Npcap y permisos de administrador.</p>
    {contextMenu?.device && <div className="device-menu-scrim" onMouseDown={() => setContextMenu(null)} onContextMenu={event => { event.preventDefault(); setContextMenu(null); }}><div className="device-context-menu" role="menu" style={{ left: contextMenu.x, top: contextMenu.y }} onMouseDown={event => event.stopPropagation()}><div className="context-device-title"><b>{contextMenu.device.hostname || contextMenu.device.address}</b><code>{contextMenu.device.address}</code></div><button role="menuitem" onClick={() => openDetails(contextMenu.device)}><Icon name="info" size={16}/> Ver detalles encontrados</button><button role="menuitem" onClick={() => { const address = contextMenu.device.address; setContextMenu(null); scanDevice(address); }}><Icon name="zap" size={16}/> Abrir en el escáner</button><button role="menuitem" disabled={busy} onClick={() => startIdentification(contextMenu.device)}><Icon name="scan" size={16}/> Escaneo TCP completo</button><small>Puede revisar hasta 65.535 puertos</small></div></div>}
    {detailDevice && <DeviceDetailDialog device={detailDevice} info={describeDevice(detailDevice, isLocalHost(detailDevice.address, networkScan?.target, system) ? system?.local_inventory : detailDevice.local_inventory, detailDevice.address === system?.gateway, (system?.adb_inventory?.devices || []).find(item => item.authorized && item.address === detailDevice.address))} localInventory={isLocalHost(detailDevice.address, networkScan?.target, system) ? system?.local_inventory : detailDevice.local_inventory} adbInfo={(system?.adb_inventory?.devices || []).find(item => item.authorized && item.address === detailDevice.address)} discovery={networkScan} busy={busy} onClose={() => setDetailDevice(null)} onIdentify={() => { setDetailDevice(null); identifyDevice(detailDevice); }}/ >}
  </main>;
}

function NetworkMap({ hosts, system, infoFor, onOpen }) {
  const gateway = hosts.find(item => item.address === system?.gateway);
  const others = hosts.filter(item => item !== gateway);
  const rings = [];
  for (let rest = others.slice(), capacity = 10; rest.length; capacity += 8) rings.push(rest.splice(0, capacity));
  const compact = others.length > 14;
  const nodes = rings.flatMap((ring, ringIndex) => ring.map((device, index) => {
    const scale = rings.length === 1 ? 0.86 : 0.42 + 0.58 * (ringIndex / (rings.length - 1));
    const angle = (index / ring.length) * Math.PI * 2 - Math.PI / 2 + ringIndex * 0.3;
    return { device, info: infoFor(device), x: 50 + Math.cos(angle) * 41 * scale, y: 50 + Math.sin(angle) * 37 * scale };
  }));
  return <div className="network-map-wrap">
    <div className="network-map" style={{ height: 460 + (rings.length - 1) * 130 }}>
      <svg viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">{nodes.map(node => <line key={node.device.address} x1="50" y1="50" x2={node.x} y2={node.y} className={node.info.isLocal ? 'is-local' : ''} vectorEffect="non-scaling-stroke"/>)}</svg>
      <button className="map-node map-router" style={{ left: '50%', top: '50%' }} onClick={() => gateway && onOpen(gateway)} disabled={!gateway} title={gateway ? 'Ver la ficha del router' : 'El router no respondió al descubrimiento'}>
        <span className="map-node-icon"><Icon name="router" size={24}/></span><b>Router</b><small>{system?.gateway || 'No detectado'}</small>
      </button>
      {nodes.map(node => <button key={node.device.address} className={`map-node ${node.info.isLocal ? 'is-local' : ''}`} style={{ left: `${node.x}%`, top: `${node.y}%` }} onClick={() => onOpen(node.device)} title={`${node.device.address} · ${node.info.deviceType} · ${node.info.os}`}>
        <span className={`map-node-icon device-${node.info.kind}`}><DeviceGlyph kind={node.info.kind}/></span>
        <b>{compact ? `.${String(node.device.address).split('.').pop()}` : node.info.name || node.device.hostname || node.device.address}</b>
        {!compact && <small>{node.info.isLocal ? 'Este equipo' : [node.info.vendor, node.info.model].filter(Boolean).join(' ') || node.info.deviceType}</small>}
      </button>)}
    </div>
    <p className="network-map-legend"><span><i className="legend-local"/>Este equipo</span><span><i/>Equipo que respondió</span><span>Haz clic en un equipo para abrir su ficha. Las líneas indican que comparten la misma red local, no el cableado real.</span></p>
  </div>;
}

function AndroidAccessPanel({ inventory }) {
  const devices = (inventory?.devices || []).filter(device => device.authorized && device.data_available);
  const message = !inventory ? 'Consultando estado de ADB…' : inventory.message;
  return <section className="android-access-panel">
    <div className="android-access-heading"><DeviceGlyph kind="android"/><div><b>Ficha Android autorizada</b><small>{devices.length ? `${devices.length} dispositivo(s) con datos disponibles por ADB` : message}</small></div></div>
    {devices.length > 0 && <div className="android-device-cards">{devices.map(device => <article key={device.serial}>
      <div><span>MODELO</span><b>{device.model || device.device_name || 'Android sin modelo anunciado'}</b><BrandBadge vendor={device.manufacturer || device.brand || ''} hostname={device.model || ''}/><small>{[device.manufacturer || device.brand, device.address].filter(Boolean).join(' · ')}</small></div>
      <div><span>SISTEMA</span><b>{device.android_version ? `Android ${device.android_version}` : 'Versión no informada'}</b><small>{device.security_patch ? `Parche ${device.security_patch}` : 'Parche no informado'}</small></div>
      <div><span>MEMORIA</span><b>{device.ram_total_bytes ? formatBytes(device.ram_total_bytes) : 'No informada'}</b><small>{device.cpu_model || device.cpu_architecture || 'Procesador no identificado'}</small></div>
      <details className="android-device-expand"><summary>Ver ficha técnica</summary><div><span>Parche de seguridad</span><b>{device.security_patch || 'No informado'}</b><span>RAM disponible</span><b>{device.ram_available_bytes ? formatBytes(device.ram_available_bytes) : 'No informada'}</b><span>Arquitectura</span><b>{device.cpu_architecture || 'No informada'}</b><span>Almacenamiento total / libre</span><b>{device.storage_total_bytes ? `${formatBytes(device.storage_total_bytes)} / ${formatBytes(device.storage_available_bytes)}` : 'No informado'}</b><span>Compilación</span><b>{device.build || 'No informada'}</b><span>SDK de Android</span><b>{device.android_sdk || 'No informado'}</b></div></details>
    </article>)}</div>}
    <p>Android requiere un teléfono ya conectado y autorizado en ADB. iPhone/iPad requiere inscripción en un servidor MDM existente.</p>
  </section>;
}

function BrandBadge({ vendor, hostname = '' }) {
  const evidence = `${vendor} ${hostname}`.toLowerCase();
  const brands = [
    { key: 'redmi', match: /redmi/, label: 'Redmi' },
    { key: 'xiaomi', match: /xiaomi|poco/, label: 'Xiaomi / POCO' },
    { key: 'motorola', match: /motorola/, label: 'Motorola' },
    { key: 'tecno', match: /tecno/, label: 'TECNO' },
    { key: 'samsung', match: /samsung/, label: 'Samsung' },
    { key: 'apple', match: /apple/, label: 'Apple' },
    { key: 'huawei', match: /huawei/, label: 'Huawei' },
    { key: 'honor', match: /honor/, label: 'HONOR' },
    { key: 'google', match: /google/, label: 'Google' },
    { key: 'google', match: /pixel/, label: 'Google Pixel' },
  ];
  const brand = brands.find(item => item.match.test(evidence));
  if (!brand) return null;
  const marks = {
    redmi: <><path d="M5 19V7h8.5a4 4 0 0 1 0 8H9m5-1 5 5"/><path d="M19 8v11"/></>,
    xiaomi: <><rect x="4" y="2.5" width="24" height="19" rx="5"/><text x="16" y="16.5" textAnchor="middle">mi</text></>,
    motorola: <><circle cx="16" cy="12" r="10"/><path d="M7 17V8l4.5 5L16 8l4.5 5L25 8v9"/></>,
    tecno: <><path d="M5 5h22M16 5v15M10 20h12"/><circle cx="16" cy="20" r="1.4" fill="currentColor"/></>,
    samsung: <><path d="M23 7.5c-1.5-2-4-3-7-3-4.6 0-7.5 2.2-7.5 5.3 0 6.3 14 2.2 14 7.4 0 2.8-2.7 4.9-7.4 4.9-3.1 0-5.7-.9-7.5-2.7"/><path d="m10 14 12-4"/></>,
    apple: <path d="M17.4 11.1c0-2.1 1.7-3.1 1.8-3.2a4.4 4.4 0 0 0-3.4-1.8c-1.5-.1-2.8.9-3.6.9s-1.9-.9-3.1-.8a4.8 4.8 0 0 0-4 2.4c-1.7 3-.4 7.3 1.2 9.8.8 1.2 1.6 2.4 2.8 2.3 1.1-.1 1.5-.8 2.9-.8s1.8.8 3 .8c1.2 0 2-.1 2.7-1.3.9-1.3 1.2-2.5 1.2-2.6-.1 0-2.5-1-2.5-4Zm-2.3-6.3a4.3 4.3 0 0 0 1.1-3.1 4.5 4.5 0 0 0-3 1.5 4 4 0 0 0-1.1 3 3.8 3.8 0 0 0 3-.9Z" fill="currentColor" stroke="none"/>,
    huawei: <><path d="M16 11c-3.8-2.3-4.9-5.9-2.9-8.1 3.5 1.2 5.2 4.2 2.9 8.1Zm1 1c2.3-3.8 5.9-4.9 8.1-2.9-1.2 3.5-4.2 5.2-8.1 2.9Zm-1 1c3.8 2.3 4.9 5.9 2.9 8.1-3.5-1.2-5.2-4.2-2.9-8.1Zm-1-1c-2.3 3.8-5.9 4.9-8.1 2.9 1.2-3.5 4.2-5.2 8.1-2.9Z"/><circle cx="16" cy="12" r="1.5" fill="currentColor"/></>,
    honor: <><path d="M4 7.5h8l4 4.5 4-4.5h8M4 16.5h8l4-4.5 4 4.5h8"/></>,
    google: <><path d="M26 12.2a10 10 0 1 1-2.9-6.8"/><path d="M26 12.2h-9"/></>,
  };
  return <span className={`vendor-logo vendor-${brand.key}`} aria-label={`Marca estimada: ${brand.label}`} title={`Marca estimada por fabricante o nombre anunciado: ${brand.label}`}><svg viewBox="0 0 32 24" aria-hidden="true">{marks[brand.key]}</svg><span>{brand.label}</span></span>;
}

function DeviceOperatingSystemSection({ matches, info, localInventory }) {
  return <section className="device-detail-section">
    <div className="device-detail-section-title"><h3>{localInventory ? 'Sistema operativo de este equipo' : 'Sistema operativo probable'}</h3>{!localInventory && info.accuracy != null && <span>{info.accuracy}% coincidencia estimada</span>}</div>
    {localInventory ? <div className="local-os-value"><b>{localInventory.os_name || info.os}</b><span>Leído localmente en este computador</span></div> : matches.length ? <><div className="device-match-list">{matches.slice(0, 6).map((match, index) => { const osClass = match.classes?.[0]; return <article key={`${match.name}-${index}`}><b>{match.name || 'Coincidencia sin nombre'}</b><span>{match.accuracy}%</span><small>{[osClass?.vendor, osClass?.family, osClass?.generation, osClass?.type].filter(Boolean).join(' · ') || 'Huella de red'}</small>{osClass?.cpe?.map(cpe => <code key={cpe}>{cpe}</code>)}</article>; })}</div><p className="device-detail-empty">La huella puede aproximar una familia; no confirma por sí sola la versión exacta ni los componentes internos.</p></> : <p className="device-detail-empty">No se obtuvo una versión de sistema suficientemente clara. Solo se muestra cuando una fuente local o una administración autorizada la confirma.</p>}
  </section>;
}

function DeviceDetailDialog({ device, info, localInventory, adbInfo, discovery, busy, onClose, onIdentify }) {
  const matches = device.os_matches || [];
  const allPorts = device.ports || [];
  const visiblePorts = allPorts.filter(port => ['open', 'filtered', 'open|filtered', 'closed|filtered'].includes(port.state));
  const scripts = [...(device.scripts || []), ...allPorts.flatMap(port => (port.scripts || []).map(script => ({ ...script, port: port.port, protocol: port.protocol })))];
  const names = [...new Set([device.hostname, ...(device.hostnames || [])].filter(Boolean))];
  const metadata = device.identification_scan;
  const displayInfo = info;
  const announced = device.evidence || {};
  return <div className="device-detail-scrim" onMouseDown={onClose}><section className="device-detail-dialog" role="dialog" aria-modal="true" aria-labelledby="device-detail-title" onMouseDown={event => event.stopPropagation()}>
    <header className="device-detail-header"><div className={`device-icon device-${displayInfo.kind}`}><DeviceGlyph kind={displayInfo.kind}/></div><div><span className="panel-kicker">FICHA DEL DISPOSITIVO</span><h2 id="device-detail-title">{adbInfo?.device_name || info.name || names[0] || device.address}</h2><p>{[info.deviceType, info.vendor, info.model].filter(Boolean).join(' · ')}</p></div><button className="device-detail-close" onClick={onClose} aria-label="Cerrar detalles"><Icon name="x" size={18}/></button></header>
    <div className="device-detail-content">
      <section className="device-detail-section identity-section"><div className="device-detail-section-title"><h3>Qué es este dispositivo</h3><span className={`tag confidence-tag confidence-${info.confidence}`}>{CONFIDENCE_LABELS[info.confidence]}</span></div>
        <div className="device-fact-grid"><div><span>Tipo</span><b>{info.deviceType}</b></div><div><span>Marca</span><b>{info.vendor || 'No anunciada'}</b></div><div><span>Modelo</span><b>{info.model || 'No anunciado'}</b></div><div><span>Sistema operativo</span><b>{info.os}</b></div></div>
        <h4>Por qué lo sabemos</h4>
        <ul className="reason-list">{info.reasons.map((reason, index) => <li key={index}><i className={`confidence-dot confidence-${reason.confidence}`} title={CONFIDENCE_LABELS[reason.confidence]}/><span>{reason.text}</span></li>)}</ul>
        {(announced.mdns || announced.upnp) && <details className="data-disclosure"><summary><span>DATOS EN BRUTO QUE ANUNCIÓ EL EQUIPO</span><Icon name="chevron-down" size={14}/></summary><div className="announce-list">
          {announced.mdns?.services?.length > 0 && <div><span>Servicios mDNS</span><code>{announced.mdns.services.join('  ')}</code></div>}
          {Object.entries(announced.mdns?.txt || {}).map(([service, values]) => <div key={service}><span>{service}</span><code>{Object.entries(values).filter(([, value]) => value).map(([key, value]) => `${key}=${value}`).join('  ')}</code></div>)}
          {(announced.upnp?.descriptions || []).map((item, index) => <div key={index}><span>Ficha UPnP</span><code>{Object.entries(item).filter(([, value]) => value).map(([key, value]) => `${key}: ${value}`).join('\n')}</code></div>)}
          {(announced.upnp?.servers || []).map(server => <div key={server}><span>Servidor UPnP</span><code>{server}</code></div>)}
          {announced.ttl && <div><span>TTL del ping</span><code>{announced.ttl}</code></div>}
        </div></details>}
      </section>
      <section className="device-detail-section"><h3>Identidad de red</h3><div className="device-fact-grid"><div><span>IP</span><code>{device.address || '—'}</code></div><div><span>MAC de interfaz</span><code>{device.mac || 'No informada por el escaneo'}</code></div><div><span>Fabricante OUI estimado</span><b>{device.mac_vendor || 'No identificado'}</b></div><div><span>Nombres anunciados</span><b>{names.length ? names.join(', ') : 'Sin nombre anunciado'}</b></div><div><span>Distancia estimada</span><b>{device.distance_hops != null ? `${device.distance_hops} saltos` : 'No disponible'}</b></div><div><span>Tiempo encendido estimado</span><b>{device.uptime_seconds != null ? `${Math.floor(device.uptime_seconds / 86400)} días` : 'No disponible'}</b></div></div><p className="device-detail-empty mac-explanation">La MAC identifica la interfaz de red en este segmento. El fabricante se estima por su prefijo; los móviles pueden usar una MAC privada aleatoria, así que la marca OUI puede faltar o no coincidir con la marca comercial del teléfono.</p></section>
      {adbInfo && <section className="device-detail-section"><h3>Datos Android leídos en el dispositivo</h3><div className="device-fact-grid"><div><span>Fabricante y modelo</span><b>{[adbInfo.manufacturer || adbInfo.brand, adbInfo.model].filter(Boolean).join(' ') || 'No informados'}</b></div><div><span>Versión de Android</span><b>{adbInfo.android_version ? `Android ${adbInfo.android_version}` : 'No informada'}</b></div><div><span>Parche de seguridad</span><b>{adbInfo.security_patch || 'No informado'}</b></div><div><span>Memoria RAM total</span><b>{adbInfo.ram_total_bytes ? formatBytes(adbInfo.ram_total_bytes) : 'No informada'}</b></div><div><span>RAM disponible</span><b>{adbInfo.ram_available_bytes ? formatBytes(adbInfo.ram_available_bytes) : 'No informada'}</b></div><div><span>Procesador / SoC</span><b>{adbInfo.cpu_model || 'No informado'}</b></div><div><span>Arquitectura</span><b>{adbInfo.cpu_architecture || 'No informada'}</b></div><div><span>Almacenamiento libre</span><b>{adbInfo.storage_available_bytes ? `${formatBytes(adbInfo.storage_available_bytes)} disponibles` : 'No informado'}</b></div></div><p className="device-detail-empty">Lectura directa por ADB desde un teléfono ya autorizado. Android no expone de forma genérica el nombre de la cuenta personal; el nombre mostrado, si existe, es solo la etiqueta del dispositivo.</p></section>}
      {!adbInfo && (localInventory || matches.length > 0) && <DeviceOperatingSystemSection matches={matches} info={info} localInventory={localInventory}/>}
      <section className="device-detail-section"><div className="device-detail-section-title"><h3>Puertos y servicios que respondieron</h3><span>{visiblePorts.length} resultados</span></div>{visiblePorts.length ? <div className="device-detail-ports">{visiblePorts.map(port => { const listener = localInventory?.tcp_listeners?.find(item => Number(item.port) === Number(port.port)); return <div key={`${port.port}/${port.protocol}`}><code>{port.port}/{port.protocol}</code><b>{port.name || port.service || 'Servicio desconocido'}</b><span>{[port.product, port.version].filter(Boolean).join(' ') || port.service || '—'}</span><em>{port.state}</em><small>Aplicación: {listener?.application || port.application || 'No identificada'}{listener ? ` · PID ${listener.pid || '—'}` : ''}</small>{port.application_source && <small>{port.application_source}</small>}{port.description && <small className="port-explanation">{port.description}{port.recommendation ? ` Recomendación: ${port.recommendation}` : ''}</small>}{port.cpe?.length > 0 && <small>{port.cpe.join(' · ')}</small>}</div>; })}</div> : <p className="device-detail-empty">El descubrimiento inicial solo comprobó qué equipos respondían; todavía no consultó sus puertos. Usa “Escaneo TCP completo” para detectar sus servicios.</p>}</section>
      {scripts.length > 0 && <section className="device-detail-section"><h3>Datos que entregaron los scripts NSE</h3><div className="device-script-results">{scripts.map((script, index) => <article key={`${script.id}-${index}`}><b>{script.id}{script.port ? ` · ${script.port}/${script.protocol}` : ''}</b><pre>{script.output || (script.details || []).join('\n') || 'El script no devolvió texto.'}</pre></article>)}</div></section>}
      <section className="device-detail-section"><h3>Escaneos realizados</h3><div className="device-fact-grid"><div><span>Descubrimiento</span><b>{discovery?.nmap_version ? `Nmap ${discovery.nmap_version} · ${discovery.target}` : 'Sin datos'}</b></div><div><span>Identificación ampliada</span><b>{metadata ? `Nmap ${metadata.nmap_version || '—'} · ${metadata.elapsed_seconds != null ? `${metadata.elapsed_seconds.toFixed(1)} s` : 'tiempo no disponible'}` : 'Aún no ejecutada'}</b></div>{metadata?.command && <div className="device-command-fact"><span>Comando usado</span><code>{metadata.command}</code></div>}</div></section>
      {localInventory && <LocalMachineDetails inventory={localInventory} nmapPorts={visiblePorts}/>}
      {!localInventory && <aside className="device-data-limits"><b>Datos privados del equipo remoto</b><p>Nmap no puede leer RAM, componentes ni la cuenta iniciada de forma genérica. SMB puede revelar nombre, dominio y SO si el host lo permite. El inventario remoto requiere un agente o administración autenticada y autorizada en cada dispositivo.</p></aside>}
    </div>
    <footer className="device-detail-footer"><span>La marca se estima por fabricante/MAC o nombre anunciado; no confirma el modelo ni el dueño.</span><button className="launch-button" disabled={busy} onClick={onIdentify}><Icon name={busy ? 'loader' : 'scan'} size={15} className={busy ? 'spin' : ''}/>{busy ? 'Analizando…' : 'Escaneo TCP completo'}</button></footer>
  </section></div>;
}

function ProfileButton({ active, onClick, icon, title, subtitle }) {
  return <button type="button" className={`profile-button ${active ? 'active' : ''}`} onClick={onClick} aria-pressed={active}>
    <span className="profile-icon"><Icon name={icon} size={15}/></span><span className="profile-text"><b>{title}</b><small>{subtitle}</small></span>{active && <span className="profile-tick"><Icon name="check" size={11}/></span>}
  </button>;
}

function CheckOption({ checked, onChange, label, disabled = false }) {
  return <label className={`check-option ${disabled ? 'is-disabled' : ''}`}><input type="checkbox" checked={checked} disabled={disabled} onChange={event => onChange(event.target.checked)}/><span className="check-box">{checked && <Icon name="check" size={11}/>}</span><span>{label}</span></label>;
}

function readableLogMessage(message) {
  if (String(message || '').includes('Traceback (most recent call last)')) return 'Falló el motor de Python; revisa el objetivo y los parámetros.';
  return message || '';
}

function LogSnippet({ log }) {
  const icon = log.type === 'scan-error' ? 'alert' : log.type === 'scan-complete' ? 'check' : 'activity';
  const message = readableLogMessage(log.message);
  return <div className={`log-snippet log-${log.type}`}><span className="log-symbol"><Icon name={icon} size={13}/></span><span className="log-copy"><b>{log.target || message || 'Actividad de TrabaMap'}</b><small>{message || log.type}</small></span><span className="log-clock">{log.time ? new Date(log.time).toLocaleTimeString('es-CO', { hour: '2-digit', minute: '2-digit' }) : ''}</span></div>;
}

function HistoryView({ reports, detail, setDetail, openSavedReport, setView, exportReport }) {
  const [reportTab, setReportTab] = useState('resumen');
  const [historyFilter, setHistoryFilter] = useState('todos');
  useEffect(() => setReportTab('resumen'), [detail?.report_file]);
  const reportIndex = detail ? reports.findIndex(report => report.name === detail.report_file) : -1;
  const baseline = reportIndex >= 0 ? reports.slice(reportIndex + 1).find(report => report.target === detail.target) : null;
  const currentOpen = new Set((detail?.hosts || []).flatMap(savedHost => savedHost.ports?.filter(port => port.state === 'open').map(port => `${port.port}/${port.protocol}`) || []));
  const previousOpen = new Set(baseline?.open_ports || []);
  const addedPorts = [...currentOpen].filter(port => !previousOpen.has(port));
  const closedPorts = [...previousOpen].filter(port => !currentOpen.has(port));
  const detailHosts = detail?.hosts || [];
  const detailPorts = detailHosts.flatMap(savedHost => (savedHost.ports || []).map(port => ({ ...port, host: savedHost })));
  const detailScripts = detailHosts.flatMap(savedHost => [
    ...(savedHost.scripts || []).map(script => ({ ...script, host: savedHost, port: null })),
    ...(savedHost.ports || []).flatMap(port => (port.scripts || []).map(script => ({ ...script, host: savedHost, port }))),
  ]);
  const filteredReports = reports.filter(report => historyFilter === 'todos' || (historyFilter === 'puertos' ? Number(report.summary?.open_ports || 0) > 0 : Number(report.summary?.high_risk || 0) > 0));

  if (detail) return <main className="page">
    <div className="secondary-top"><button className="back-button" onClick={() => setDetail(null)}><Icon name="arrow-left" size={15}/> Historial</button><span className="file-badge"><Icon name="file" size={14}/> REPORTE JSON</span></div>
    <div className="detail-header"><span className="panel-kicker">ANÁLISIS GUARDADO</span><h1>{detail.target}</h1><p>{fmtDate(detail.created_at)} · Nmap {detail.nmap_version}</p><div className="detail-actions"><button onClick={() => exportReport(detail)}><Icon name="table" size={14}/> Exportar a Excel</button><button onClick={() => setView('scan')}><Icon name="scan" size={14}/> Volver al escáner</button><button onClick={() => detail.report_file && api.openReport(detail.report_file)}><Icon name="download" size={14}/> Abrir JSON</button><button onClick={() => detail.raw_xml_file && api.openReport(detail.raw_xml_file)}><Icon name="code" size={14}/> XML original</button></div></div>
    <div className="detail-metrics"><Metric label="PUERTOS ABIERTOS" value={detail.summary?.open_ports || 0} icon="wifi" sub="Detectados"/><Metric label="RIESGO ALTO" value={detail.summary?.high_risk || 0} icon="shield-alert" sub="Para revisar"/><Metric label="EQUIPOS" value={detail.summary?.hosts || 0} icon="server" sub="Que respondieron"/></div>
    <nav className="report-tabs" aria-label="Secciones del informe">{[['resumen', 'Resumen'], ['dispositivos', `Dispositivos · ${detailHosts.length}`], ['puertos', `Puertos · ${detailPorts.length}`], ['nse', `Scripts NSE · ${detailScripts.length}`], ['evidencia', 'Método y límites']].map(([id, label]) => <button key={id} className={reportTab === id ? 'active' : ''} onClick={() => setReportTab(id)}>{label}</button>)}</nav>
    {reportTab === 'resumen' && <><section className="report-diff"><div><span className="panel-kicker">CAMBIO DE SERVICIOS</span><b>{baseline ? 'Comparación con el análisis anterior del mismo objetivo' : 'Primer análisis guardado de este objetivo'}</b><small>{baseline ? fmtDate(baseline.date) : 'Guarda otro análisis para detectar puertos nuevos o cerrados.'}</small></div>{baseline && <div className="diff-pills"><span>+ {addedPorts.length} nuevos{addedPorts.length > 0 && ` · ${addedPorts.join(', ')}`}</span><span>− {closedPorts.length} cerrados{closedPorts.length > 0 && ` · ${closedPorts.join(', ')}`}</span></div>}</section><div className="saved-hosts">{detailHosts.map(savedHost => <article className="saved-host" key={savedHost.address}><div className="host-line"><Icon name="server" size={15}/><b>{savedHost.hostname || savedHost.address}</b><span>{savedHost.address}</span><i className={savedHost.status === 'up' ? 'up' : ''}/>{savedHost.status}</div><div className="report-host-facts"><span>MAC <b>{savedHost.mac || 'No informada'}</b></span><span>Fabricante OUI <b>{savedHost.mac_vendor || 'No identificado'}</b></span><span>Puertos abiertos <b>{savedHost.ports?.filter(port => port.state === 'open').length || 0}</b></span><span>SO probable <b>{savedHost.os_matches?.[0]?.name || 'Sin huella Nmap'}</b></span></div></article>)}</div></>}
    {reportTab === 'dispositivos' && <div className="report-table-wrap"><table className="report-data-table"><thead><tr><th>Equipo / hostname</th><th>IP</th><th>MAC</th><th>Fabricante OUI estimado</th><th>SO probable</th><th>Confianza</th><th>Estado</th></tr></thead><tbody>{detailHosts.map(savedHost => <tr key={savedHost.address}><td>{savedHost.hostname || 'Sin nombre anunciado'}</td><td>{savedHost.address}</td><td>{savedHost.mac || 'No informada'}</td><td>{savedHost.mac_vendor || 'No identificado'}</td><td>{savedHost.os_matches?.[0]?.name || 'No identificado'}</td><td>{savedHost.os_matches?.[0]?.accuracy != null ? `${savedHost.os_matches[0].accuracy}% estimado` : '—'}</td><td>{savedHost.status || '—'}</td></tr>)}</tbody></table><p className="report-footnote">La coincidencia de SO es una huella Nmap, no una lectura autenticada. La MAC/fabricante puede faltar o ser aleatoria en celulares.</p></div>}
    {reportTab === 'puertos' && <div className="report-table-wrap"><table className="report-data-table report-port-table"><thead><tr><th>Equipo</th><th>Puerto</th><th>Estado</th><th>Aplicación / servicio</th><th>Producto / versión</th><th>Significado y recomendación</th><th>Riesgo</th></tr></thead><tbody>{detailPorts.map((port, index) => <tr key={`${port.host.address}-${port.port}-${port.protocol}-${index}`}><td>{port.host.hostname || port.host.address}</td><td><code>{port.port}/{port.protocol}</code></td><td>{port.state}</td><td><b>{port.application || port.name || port.service || 'No identificada'}</b><small>{port.application_source || 'El número de puerto no identifica por sí solo el proceso.'}</small></td><td>{[port.product, port.version].filter(Boolean).join(' ') || 'No detectado'}</td><td><b>{port.description || 'Nmap no aportó explicación para este puerto.'}</b><small>{port.recommendation || 'Confirma si el servicio debe estar disponible.'}</small></td><td><span className={`risk-tag ${riskClass[port.risk] || 'info'}`}>{port.risk || 'Sin valorar'}</span></td></tr>)}</tbody></table>{detailPorts.length === 0 && <EmptyState icon="wifi" title="Este informe no contiene puertos" text="El escaneo pudo ser solo de descubrimiento de equipos."/>}</div>}
    {reportTab === 'nse' && <div className="report-script-list">{detailScripts.length ? detailScripts.map((script, index) => <article key={`${script.host.address}-${script.id}-${index}`}><header><b>{script.id || 'Script NSE'}</b><span>{script.host.hostname || script.host.address}{script.port ? ` · ${script.port.port}/${script.port.protocol}` : ' · equipo'}</span><em className={script.possible_vulnerability ? 'script-risk' : ''}>{script.possible_vulnerability ? 'Revisar hallazgo posible' : 'Sin alerta marcada'}</em></header><pre>{script.output || (script.details || []).join('\n') || 'El script no devolvió salida.'}</pre></article>) : <EmptyState icon="code" title="El informe no contiene resultados NSE" text="Los scripts no estaban habilitados o no devolvieron datos."/>}</div>}
    {reportTab === 'evidencia' && <div className="report-method"><article><span>Comando Nmap</span><code>{detail.nmap_command || detail.command || 'No guardado'}</code></article><article><span>Opciones del escaneo</span><code>{detail.options ? JSON.stringify(detail.options, null, 2) : 'No guardadas en este informe antiguo'}</code></article><article><span>Lectura de la MAC</span><p>El valor identifica la interfaz que respondió en el segmento local. El fabricante se asocia al prefijo OUI; no demuestra modelo, dueño ni marca comercial. Los teléfonos pueden anunciar direcciones privadas aleatorias.</p></article><article><span>Lectura del sistema operativo</span><p>Las coincidencias de Nmap se basan en huellas de red y pueden ser ambiguas. Nmap no revela de forma genérica la versión exacta de Android/iOS, RAM, componentes o usuario de otro dispositivo.</p></article><article><span>Identificación de aplicaciones</span><p>La detección -sV identifica producto y versión si un servicio los anuncia. En un equipo remoto, el proceso/PID no suele ser visible; si no hay respuesta, el puerto solo sugiere un protocolo habitual.</p></article><article><span>Fecha y herramienta</span><p>{fmtDate(detail.created_at)} · Nmap {detail.nmap_version || 'versión no guardada'} · {detail.elapsed_seconds != null ? `${detail.elapsed_seconds.toFixed(1)} segundos` : 'duración no guardada'}</p></article></div>}
  </main>;

  return <main className="page"><div className="secondary-title"><div><span className="panel-kicker">ARCHIVO LOCAL</span><h1>Historial de escaneos</h1><p>Abre un análisis para revisar equipos, puertos, evidencia NSE y cambios.</p></div><span className="history-total"><Icon name="history" size={16}/>{reports.length} reportes</span></div>
    <nav className="history-filter-tabs" aria-label="Filtrar historial">{[['todos', 'Todos', reports.length], ['puertos', 'Con puertos abiertos', reports.filter(item => Number(item.summary?.open_ports || 0) > 0).length], ['riesgo', 'Para revisar', reports.filter(item => Number(item.summary?.high_risk || 0) > 0).length]].map(([id, label, count]) => <button key={id} className={historyFilter === id ? 'active' : ''} onClick={() => setHistoryFilter(id)}>{label}<span>{count}</span></button>)}</nav>
    <div className="history-table">{filteredReports.length ? filteredReports.map((report, index) => <button className="history-item" key={report.name} onClick={() => openSavedReport(report.name)}><span className="history-index">{String(filteredReports.length - index).padStart(2, '0')}</span><span className="history-file-icon"><Icon name="file" size={17}/></span><span className="history-detail"><b>{report.target}</b><small>{fmtDate(report.date)} · {report.name}</small></span><span className="history-number"><b>{report.summary?.open_ports ?? 0}</b><small>puertos abiertos</small></span><span className={`history-alert ${report.summary?.high_risk ? 'alert' : ''}`}><i/>{report.summary?.high_risk ? `${report.summary.high_risk} por revisar` : 'sin riesgo alto'}</span><Icon name="chevron-right" size={17}/></button>) : reports.length ? <EmptyState icon="filter" title="No hay informes en esta pestaña" text="Cambia el filtro para ver otros escaneos."/> : <EmptyState icon="history" title="Aún no hay escaneos guardados" text="Los resultados se guardan automáticamente después de cada análisis." action="Iniciar primer escaneo" onAction={() => setView('scan')}/>}</div>
  </main>;
}

function Metric({ label, value, icon, sub }) {
  return <div className="detail-metric"><span className="metric-icon"><Icon name={icon} size={15}/></span><span className="metric-label">{label}</span><b>{value}</b><small>{sub}</small></div>;
}

function LogsView({ logs, refresh }) {
  return <main className="page"><div className="secondary-title"><div><span className="panel-kicker">TRAZABILIDAD LOCAL</span><h1>Registro de actividad</h1><p>Escaneos iniciados, completados, cancelados y errores del motor.</p></div><button className="refresh-wide" onClick={refresh}><Icon name="refresh" size={14}/> Actualizar</button></div>
    <div className="logs-table-head"><span>EVENTO</span><span>OBJETIVO / DETALLE</span><span>HORA</span></div><div className="logs-list">{logs.length ? logs.map((log, index) => <div className="logs-row" key={`${log.time}-${index}`}><span className={`log-type type-${log.type}`}><i/>{log.type?.replace('scan-', '') || 'evento'}</span><span className="log-target"><b>{log.target || '—'}</b><small>{readableLogMessage(log.message)}</small></span><span className="logs-time">{fmtDate(log.time)}{log.elapsed_ms ? ` · ${(log.elapsed_ms / 1000).toFixed(1)} s` : ''}</span></div>) : <EmptyState icon="activity" title="Sin actividad todavía" text="El registro se actualizará al realizar el primer análisis."/>}</div>
    <div className="logs-foot"><Icon name="lock" size={13}/> Se conservan hasta 250 eventos recientes en este dispositivo.</div>
  </main>;
}

function EmptyState({ icon, title, text, action, onAction }) {
  return <div className="history-blank"><div><Icon name={icon} size={24}/></div><b>{title}</b><span>{text}</span>{action && <button onClick={onAction}>{action}<Icon name="arrow-right" size={14}/></button>}</div>;
}

// Reutiliza la raíz si el módulo se recarga en caliente durante el desarrollo.
const container = document.getElementById('root');
container.trabamapRoot ||= createRoot(container);
container.trabamapRoot.render(<React.StrictMode><App/></React.StrictMode>);
