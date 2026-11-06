import { createConnection } from 'node:net';
import { spawn } from 'node:child_process';
import { rm } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const testDir = resolve(fileURLToPath(new URL('.', import.meta.url)));
const repositoryRoot = resolve(testDir, '../..');
const host = '127.0.0.1';
const testDatabase = resolve(testDir, '.web-e2e-devices.db');

function waitForTcp(port, timeoutMs = 8_000) {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolveReady, reject) => {
    const tryConnect = () => {
      const socket = createConnection({ host, port });
      socket.once('connect', () => {
        socket.destroy();
        resolveReady();
      });
      socket.once('error', () => {
        socket.destroy();
        if (Date.now() >= deadline) {
          reject(new Error(`Simulator did not listen on ${host}:${port}`));
          return;
        }
        setTimeout(tryConnect, 100);
      });
    };
    tryConnect();
  });
}

export default async function globalSetup() {
  await rm(testDatabase, { force: true });
  const python = process.env.PYTHON || 'python';
  const definitions = [
    {
      name: 'Modbus',
      port: 1502,
      args: [resolve(repositoryRoot, 'sim', 'modbus_sim.py'), '--host', host, '--port', '1502'],
    },
    {
      name: 'Beckhoff ADS',
      port: 14898,
      args: [
        resolve(repositoryRoot, 'sim', 'beckhoff_sim.py'),
        '--host', host,
        '--ads-port', '14898',
        '--discovery-port', '48899',
      ],
    },
    {
      name: 'Mitsubishi SLMP',
      port: 15007,
      args: [resolve(repositoryRoot, 'sim', 'slmp_sim.py'), '--host', host, '--port', '15007'],
    },
  ];
  const children = definitions.map(({ name, port, args }) => {
    const child = spawn(python, args, {
      cwd: repositoryRoot,
      stdio: 'ignore',
      windowsHide: true,
    });
    child.once('error', error => {
      throw new Error(`Could not start the ${name} simulator: ${error.message}`);
    });
    return { child, port };
  });
  await Promise.all(children.map(({ port }) => waitForTcp(port)));
  return async () => {
    for (const { child } of children) {
      if (!child.killed) {
        child.kill();
      }
    }
    await rm(testDatabase, { force: true });
  };
}
