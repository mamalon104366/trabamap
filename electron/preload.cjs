const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('trabamap', {
  scan: options => ipcRenderer.invoke('tmap:scan', options),
  cancelScan: () => ipcRenderer.invoke('tmap:cancel-scan'),
  onScanProgress: callback => { const listener = (_event, payload) => callback(payload); ipcRenderer.on('tmap:scan-progress', listener); return () => ipcRenderer.removeListener('tmap:scan-progress', listener); },
  reports: () => ipcRenderer.invoke('tmap:reports'),
  logs: () => ipcRenderer.invoke('tmap:logs'),
  report: name => ipcRenderer.invoke('tmap:report', name),
  openReport: name => ipcRenderer.invoke('tmap:open-report', name),
  exportExcel: report => ipcRenderer.invoke('tmap:export-excel', report),
  system: () => ipcRenderer.invoke('tmap:system'),
  identify: request => ipcRenderer.invoke('tmap:identify', request),
  policyCheck: request => ipcRenderer.invoke('tmap:policy-check', request),
  settings: () => ipcRenderer.invoke('tmap:settings-get'),
  installNmap: () => ipcRenderer.invoke('tmap:nmap-install'),
  onNmapInstall: callback => { const listener = (_event, payload) => callback(payload); ipcRenderer.on('tmap:nmap-install-progress', listener); return () => ipcRenderer.removeListener('tmap:nmap-install-progress', listener); },
  saveSettings: value => ipcRenderer.invoke('tmap:settings-set', value)
});
