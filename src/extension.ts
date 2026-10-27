import type { ExtensionAPI } from '@earendil-works/pi-coding-agent';
import { TpLinkGdprClient } from './index.ts';

const USERNAME_VARIABLE = 'TPLINK_USERNAME';
const PASSWORD_VARIABLE = 'TPLINK_PASSWORD';

function readCredentials(): { username: string; password: string } {
  const username = process.env[USERNAME_VARIABLE] ?? '';
  const password = process.env[PASSWORD_VARIABLE] ?? '';
  if (username === '' || password === '') {
    throw new Error(`${USERNAME_VARIABLE} and ${PASSWORD_VARIABLE} must both be set`);
  }
  return { username, password };
}

export default function newIpExtension(pi: ExtensionAPI): void {
  pi.registerCommand('new-ip', {
    description: 'Reconnect the GPON WAN of the TP-Link router to obtain a new IP',
    handler: async (_args, ctx) => {
      try {
        const client = new TpLinkGdprClient(readCredentials());
        await client.login();
        const previousAddress = (await client.gponWan()).connIPv4Address;
        const connection = await client.reconnectGponWan();
        ctx.ui.notify(`WAN IP address refreshed ${previousAddress} -> ${connection.connIPv4Address}`, 'info');
      } catch (error) {
        ctx.ui.notify(error instanceof Error ? error.message : String(error), 'error');
      }
    }
  });
}
