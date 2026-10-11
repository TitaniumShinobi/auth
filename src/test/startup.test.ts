import assert from 'node:assert/strict';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const entrypoint = path.resolve(__dirname, '..', 'index.js');

type StartupSample = {
  child: ChildProcessWithoutNullStreams;
  healthReadyMs: number;
  port: number;
};

function startMeasuredProcess(): Promise<StartupSample> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [entrypoint], {
      env: {
        ...process.env,
        AUTH_PORT: '0',
        AUTH_STORAGE_ADAPTER: 'memory',
        AUTH_EPHEMERAL_STORE: 'memory',
      },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let output = '';
    const timeout = setTimeout(() => {
      child.kill();
      reject(new Error(`Timed out waiting for startup diagnostics:\n${output}`));
    }, 5_000);
    const onOutput = (chunk: Buffer) => {
      output += chunk.toString();
      const match = output.match(/\[startup\] health_ready_ms=([\d.]+) port=(\d+)/);
      if (!match) return;
      clearTimeout(timeout);
      resolve({
        child,
        healthReadyMs: Number(match[1]),
        port: Number(match[2]),
      });
    };
    child.stdout.on('data', onOutput);
    child.stderr.on('data', onOutput);
    child.once('error', (error) => {
      clearTimeout(timeout);
      reject(error);
    });
    child.once('exit', (code) => {
      if (code && !output.includes('[startup] health_ready_ms=')) {
        clearTimeout(timeout);
        reject(new Error(`Auth exited ${code} before readiness:\n${output}`));
      }
    });
  });
}

async function stop(sample: StartupSample) {
  if (sample.child.exitCode !== null) return;
  sample.child.kill('SIGTERM');
  await new Promise<void>((resolve) => sample.child.once('exit', () => resolve()));
}

test('cold process startup benchmark reaches a healthy listener', async () => {
  const sample = await startMeasuredProcess();
  try {
    console.log(`[benchmark] cold_health_ready_ms=${sample.healthReadyMs}`);
    const response = await fetch(`http://127.0.0.1:${sample.port}/health`);
    assert.equal(response.status, 200);
    const payload = await response.json() as { ok?: boolean; state?: string };
    assert.equal(payload.ok, true);
    if (payload.state !== undefined) {
      assert.ok(['HEALTH_READY', 'OPTIONAL_SERVICES_READY'].includes(payload.state));
    }
    assert.ok(Number.isFinite(sample.healthReadyMs));
  } finally {
    await stop(sample);
  }
});

test('warm process startup reaches health in under 100ms', async () => {
  const cachePrimer = await startMeasuredProcess();
  await stop(cachePrimer);

  const sample = await startMeasuredProcess();
  try {
    console.log(`[benchmark] warm_health_ready_ms=${sample.healthReadyMs}`);
    assert.ok(
      sample.healthReadyMs < 100,
      `warm health readiness was ${sample.healthReadyMs}ms (target <100ms)`,
    );
    const response = await fetch(`http://127.0.0.1:${sample.port}/health`);
    assert.equal(response.status, 200);
  } finally {
    await stop(sample);
  }
});

test('readiness is distinct from early process health', async () => {
  const sample = await startMeasuredProcess();
  try {
    let payload: { ok?: boolean; ready?: boolean } = {};
    let status = 0;
    for (let attempt = 0; attempt < 50; attempt += 1) {
      const response = await fetch(`http://127.0.0.1:${sample.port}/ready`);
      status = response.status;
      payload = await response.json() as typeof payload;
      if (status === 200) break;
      await new Promise(resolve => setTimeout(resolve, 10));
    }
    assert.equal(status, 200);
    assert.deepEqual(payload, { ok: true, ready: true, service: 'auth' });
  } finally {
    await stop(sample);
  }
});
