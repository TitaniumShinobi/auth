import http from 'node:http';
import { FileAppConfigStore, getPort } from './config.js';
const elapsedMs = () => Number((process.uptime() * 1000).toFixed(2));
const logTiming = (name, extra = '') => console.log(`[startup] ${name}_ms=${elapsedMs()}${extra}`);
let state = 'BOOTING';
let initializationErrorCode = null;
logTiming('process_spawn');
logTiming('module_loading');
const port = getPort();
const host = process.env.AUTH_HOST || '127.0.0.1';
const configStore = new FileAppConfigStore();
// Validate and cache static configuration before advertising readiness. This is
// the only filesystem-backed dependency required by the health path.
await configStore.getConfig();
state = 'CONFIG_READY';
logTiming('config_loaded');
let requestHandler = (req, res) => {
    if (req.url === '/health' || req.url?.startsWith('/health?')) {
        res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ ok: true, service: 'auth', state }));
        return;
    }
    if (req.url === '/ready' || req.url?.startsWith('/ready?')) {
        res.writeHead(503, {
            'content-type': 'application/json; charset=utf-8',
            'retry-after': '1',
        });
        res.end(JSON.stringify({
            ok: false,
            ready: false,
            service: 'auth',
            error: initializationErrorCode || 'AUTH_INITIALIZING',
            state,
        }));
        return;
    }
    res.writeHead(503, {
        'content-type': 'application/json; charset=utf-8',
        'retry-after': '1',
    });
    res.end(JSON.stringify({
        ok: false,
        error: 'AUTH_INITIALIZING',
        state,
    }));
};
const server = http.createServer((req, res) => requestHandler(req, res));
server.once('error', (error) => {
    if (error.code === 'EADDRINUSE') {
        console.error(`[auth] startup refused: port ${port} is already occupied`);
    }
    else {
        console.error('[auth] listener failed', error);
    }
    process.exitCode = 1;
});
server.listen(port, host, () => {
    state = 'HEALTH_READY';
    const address = server.address();
    const listeningPort = address && typeof address === 'object' ? address.port : port;
    logTiming('health_ready', ` port=${listeningPort}`);
    console.log(`[auth] primary listening on http://${host}:${listeningPort}`);
    setImmediate(async () => {
        try {
            const moduleStartedAt = elapsedMs();
            const { createAuthApp } = await import('./app.js');
            logTiming('auth_modules_loaded');
            const app = await createAuthApp({ configStore });
            requestHandler = app;
            state = 'OPTIONAL_SERVICES_READY';
            logTiming('routes_ready', ` deferred_init_ms=${(elapsedMs() - moduleStartedAt).toFixed(2)}`);
            console.log('[auth] optional services ready');
        }
        catch (error) {
            initializationErrorCode =
                error && typeof error === 'object' && 'code' in error
                    ? String(error.code || 'AUTH_INITIALIZATION_FAILED')
                    : 'AUTH_INITIALIZATION_FAILED';
            console.error('[auth] optional service initialization failed', error);
            // Keep health available for supervision while all protected/API routes
            // fail closed with 503.
        }
    });
});
