import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const entrypoint = path.resolve(__dirname, '..', 'index.js');
function startMeasuredProcess() {
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
        const onOutput = (chunk) => {
            output += chunk.toString();
            const match = output.match(/\[startup\] health_ready_ms=([\d.]+) port=(\d+)/);
            if (!match)
                return;
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
async function stop(sample) {
    if (sample.child.exitCode !== null)
        return;
    sample.child.kill('SIGTERM');
    await new Promise((resolve) => sample.child.once('exit', () => resolve()));
}
test('cold process startup benchmark reaches a healthy listener', async () => {
    const sample = await startMeasuredProcess();
    try {
        console.log(`[benchmark] cold_health_ready_ms=${sample.healthReadyMs}`);
        const response = await fetch(`http://127.0.0.1:${sample.port}/health`);
        assert.equal(response.status, 200);
        const payload = await response.json();
        assert.equal(payload.ok, true);
        assert.ok(['HEALTH_READY', 'OPTIONAL_SERVICES_READY'].includes(payload.state || ''));
        assert.ok(Number.isFinite(sample.healthReadyMs));
    }
    finally {
        await stop(sample);
    }
});
test('warm process startup reaches health in under 100ms', async () => {
    const cachePrimer = await startMeasuredProcess();
    await stop(cachePrimer);
    const sample = await startMeasuredProcess();
    try {
        console.log(`[benchmark] warm_health_ready_ms=${sample.healthReadyMs}`);
        assert.ok(sample.healthReadyMs < 100, `warm health readiness was ${sample.healthReadyMs}ms (target <100ms)`);
        const response = await fetch(`http://127.0.0.1:${sample.port}/health`);
        assert.equal(response.status, 200);
    }
    finally {
        await stop(sample);
    }
});
test('readiness is distinct from early process health', async () => {
    const sample = await startMeasuredProcess();
    try {
        let payload = {};
        let status = 0;
        for (let attempt = 0; attempt < 50; attempt += 1) {
            const response = await fetch(`http://127.0.0.1:${sample.port}/ready`);
            status = response.status;
            payload = await response.json();
            if (status === 200)
                break;
            await new Promise(resolve => setTimeout(resolve, 10));
        }
        assert.equal(status, 200);
        assert.deepEqual(payload, { ok: true, ready: true, service: 'auth' });
    }
    finally {
        await stop(sample);
    }
});
