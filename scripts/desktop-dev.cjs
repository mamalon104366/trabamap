const { spawn } = require('node:child_process');
const net = require('node:net');
const path = require('node:path');
const http = require('node:http');

const root = path.resolve(__dirname, '..');
const viteCli = path.join(root, 'node_modules', 'vite', 'bin', 'vite.js');
const electronCli = path.join(root, 'node_modules', 'electron', 'cli.js');

function getFreePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close(error => error ? reject(error) : resolve(port));
    });
  });
}

function waitForServer(url, child, timeoutMs = 20000) {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    const check = () => {
      if (child.exitCode !== null) return reject(new Error('Vite terminó antes de iniciar.'));
      const request = http.get(url, response => {
        response.resume();
        if (response.statusCode >= 200 && response.statusCode < 500) return resolve();
        retry();
      });
      request.setTimeout(700, () => request.destroy());
      request.on('error', retry);
    };
    const retry = () => {
      if (Date.now() - started > timeoutMs) return reject(new Error('Vite no respondió dentro del tiempo esperado.'));
      setTimeout(check, 150);
    };
    check();
  });
}

async function main() {
  const port = await getFreePort();
  const url = `http://127.0.0.1:${port}`;
  const vite = spawn(process.execPath, [viteCli, '--host', '127.0.0.1', '--port', String(port), '--strictPort'], {
    cwd: root,
    stdio: 'inherit',
    windowsHide: true,
  });
  let electron;
  let stopping = false;
  const stop = code => {
    if (stopping) return;
    stopping = true;
    if (electron && electron.exitCode === null) electron.kill();
    if (vite.exitCode === null) vite.kill();
    process.exitCode = code;
  };
  process.once('SIGINT', () => stop(130));
  process.once('SIGTERM', () => stop(143));
  vite.once('error', error => { console.error(`No se pudo iniciar Vite: ${error.message}`); stop(1); });
  vite.once('exit', code => {
    if (!stopping && code !== 0) {
      console.error('El servidor de TrabaMap se cerró. No se abrirá una ventana conectada a otra instancia.');
      stop(code || 1);
    }
  });

  try {
    await waitForServer(url, vite);
    console.log(`TrabaMap listo en ${url}`);
    electron = spawn(process.execPath, [electronCli, '.'], {
      cwd: root,
      env: { ...process.env, TRABAMAP_DEV_URL: url },
      stdio: 'inherit',
      windowsHide: false,
    });
    electron.once('error', error => { console.error(`No se pudo iniciar Electron: ${error.message}`); stop(1); });
    electron.once('exit', code => stop(code || 0));
  } catch (error) {
    console.error(error.message);
    stop(1);
  }

}

main().catch(error => { console.error(error); process.exitCode = 1; });
