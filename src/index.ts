import http, { type RequestListener } from 'node:http';

import { FileAppConfigStore, getPort } from './config.js';

type StartupState = 'BOOTING' | 'CONFIG_READY' | 'HEALTH_READY' | 'OPTIONAL_SERVICES_READY';

const elapsedMs = () => Number((process.uptime() * 1000).toFixed(2));
const logTiming = (name: string, extra = '') =>
  console.log(`[startup] ${name}_ms=${elapsedMs()}${extra}`);

let state: StartupState = 'BOOTING';
let initializationErrorCode: string | null = null;
let resourceStatusServer: ReturnType<typeof import('node:https').createServer> | undefined;
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

let requestHandler: RequestListener = (req, res) => {
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
server.once('error', (error: NodeJS.ErrnoException) => {
  if (error.code === 'EADDRINUSE') {
    console.error(`[auth] startup refused: port ${port} is already occupied`);
  } else {
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
      const { loadResourceRuntime, createResourceStatusServer } = await import('./auth/resourceRuntime.js');
      let resourceRuntime;
      try {
        resourceRuntime = loadResourceRuntime();
        if (resourceRuntime) {
          await resourceRuntime.authorization.store.initialize();
          resourceStatusServer = createResourceStatusServer(resourceRuntime, (req, res) => requestHandler(req, res));
          const listener = resourceStatusServer;
          await new Promise<void>((resolve, reject) => {
            listener.once('error', reject);
            listener.listen(resourceRuntime!.tls.port, resourceRuntime!.tls.host, () => {
              listener.removeListener('error', reject);
              resolve();
            });
          });
          listener.on('error', () => {
            listener.close();
            console.error('[auth] resource status listener unavailable');
          });
          console.log('[auth] resource status mTLS listener configured; resource admission remains independently gated');
        }
      } catch {
        resourceStatusServer?.close();
        resourceStatusServer = undefined;
        resourceRuntime = undefined;
        // Optional resource failures must not replace legacy authentication or leak configuration.
        console.error('[auth] resource runtime unavailable: RESOURCE_RUNTIME_CONFIGURATION_INVALID');
      }
      let authenticationReadiness;
      if(process.env.AUTH_RELIABILITY_MANIFEST || process.env.AUTH_RELIABILITY_ADAPTER || process.env.AUTH_RELIABILITY_ADAPTER_SHA256){
        try{
          const {createReadinessObserver}=await import('../scripts/auth-release-reliability.mjs');
          authenticationReadiness=await createReadinessObserver({manifestPath:process.env.AUTH_RELIABILITY_MANIFEST,adapterPath:process.env.AUTH_RELIABILITY_ADAPTER,adapterSha256:process.env.AUTH_RELIABILITY_ADAPTER_SHA256});
        }catch{console.error('[auth] readiness configuration unavailable');}
      }
      const app = await createAuthApp({ configStore, authenticationReadiness, resourceAuthorization: resourceRuntime?.authorization });
      requestHandler = app as RequestListener;
      state = 'OPTIONAL_SERVICES_READY';
      logTiming('routes_ready', ` deferred_init_ms=${(elapsedMs() - moduleStartedAt).toFixed(2)}`);
      console.log('[auth] optional services ready');
    } catch (error) {
      resourceStatusServer?.close();
      initializationErrorCode =
        error && typeof error === 'object' && 'code' in error
          ? String((error as { code?: unknown }).code || 'AUTH_INITIALIZATION_FAILED')
          : 'AUTH_INITIALIZATION_FAILED';
      console.error('[auth] optional service initialization failed', error);
      // Keep health available for supervision while all protected/API routes
      // fail closed with 503.
    }
  });
});
