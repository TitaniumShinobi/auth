import { createAuthApp } from './app.js';
import { FileAppConfigStore, getPort } from './config.js';

const port = getPort();
const configStore = new FileAppConfigStore();
const app = await createAuthApp({ configStore });

app.listen(port, () => {
  console.log(`[auth] primary listening on http://localhost:${port}`);
});
