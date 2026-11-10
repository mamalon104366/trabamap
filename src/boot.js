// Punto de entrada. En desarrollo, /?demo carga datos de ejemplo antes de montar la interfaz.
try { document.documentElement.dataset.theme = localStorage.getItem('trabamap.theme') === 'light' ? 'light' : 'dark'; } catch { document.documentElement.dataset.theme = 'dark'; }
const start = () => import('./main.jsx');
if (import.meta.env.DEV && !window.trabamap && new URLSearchParams(window.location.search).has('demo')) import('./demo.js').then(start);
else start();
