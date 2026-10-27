import { connect } from 'node:tls';

import { aesDecrypt, aesEncrypt, aesKeyString, createAesSession, md5Hex, rsaRawEncrypt, type AesSession, type RsaPublicKey } from './gdpr-crypto.ts';
import { parseHttpResponse, type HttpResponse } from './http-response.ts';

const DEFAULT_BASE_URL = 'https://192.168.1.1';
const DEFAULT_STACK = '0,0,0,0,0,0';
const DEFAULT_TIMEOUT_MS = 15_000;
const CONNECTED_STATUS = 'Connected';

type Operation = 'go' | 'so' | 'gl' | 'ao' | 'do' | 'op' | 'cgi';

interface Credentials {
  username: string;
  password: string;
}

export interface ClientOptions extends Credentials {
  baseUrl?: string;
}

interface DmResponse<T> {
  success: boolean;
  errorcode: number;
  data: T;
}

export interface WanConnection {
  stack: string;
  accessMode: string;
  connStatusV4: string;
  [attribute: string]: string;
}

export class RouterError extends Error {}

export class TpLinkGdprClient {
  readonly #baseUrl: string;
  readonly #credentials: Credentials;
  readonly #session: AesSession;
  #sequence = 0;
  #signatureHash = '';
  #publicKey: RsaPublicKey = { modulusHex: '', exponentHex: '' };
  #cookies = new Map<string, string>();
  #token = '0';

  constructor(options: ClientOptions) {
    this.#baseUrl = (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/$/, '');
    this.#credentials = { username: options.username, password: options.password };
    this.#session = createAesSession();
  }

  async login(): Promise<void> {
    const encryptedParameters = await this.#post('/cgi/getGDPRParm', '');
    this.#publicKey = {
      modulusHex: readAssignedString(encryptedParameters, 'nn'),
      exponentHex: readAssignedString(encryptedParameters, 'ee')
    };
    this.#sequence = Number(readAssignedString(encryptedParameters, 'seq'));
    this.#signatureHash = md5Hex(`${this.#credentials.username}${this.#credentials.password}`);

    const script = await this.#exchange('cgi', '/cgi/login', {
      UserName: toBase64(this.#credentials.username),
      Passwd: toBase64(this.#credentials.password),
      Action: '1',
      stack: DEFAULT_STACK,
      pstack: DEFAULT_STACK
    }, true);

    const errorCode = readScriptResult(script);
    if (errorCode !== 0) throw new RouterError(`Login rejected with error code ${errorCode}`);

    const page = await this.#get('/');
    const token = /var token="([^"]+)"/.exec(page)?.[1];
    if (token === undefined) throw new RouterError('Login did not produce an authenticated session');
    this.#token = token;
  }

  async cgi(oid: string, data: Record<string, string> = {}): Promise<number> {
    return readScriptResult(await this.#exchange('cgi', oid, data));
  }

  async get<T>(oid: string, data: Record<string, string> = {}): Promise<T> {
    return this.#unwrap(await this.#json<T>('go', oid, data));
  }

  async set(oid: string, data: Record<string, string>): Promise<void> {
    this.#unwrap(await this.#json('so', oid, data));
  }

  async operate(oid: string, data: Record<string, string> = {}): Promise<void> {
    this.#unwrap(await this.#json('op', oid, data));
  }

  async listWanConnections(): Promise<WanConnection[]> {
    return this.#unwrap(await this.#json<WanConnection[]>('gl', 'DEV2_ADT_WAN', {}));
  }

  async gponWan(): Promise<WanConnection> {
    const connections = await this.listWanConnections();
    const connection = connections.find(candidate => candidate.accessMode === 'PON');
    if (connection === undefined) throw new RouterError('Router reported no PON WAN connection');
    return connection;
  }

  async disconnectGponWan(): Promise<void> {
    const { stack } = await this.gponWan();
    await this.operate('ACT_PPP_DISCONN', { stack });
  }

  async connectGponWan(): Promise<void> {
    const { stack } = await this.gponWan();
    await this.operate('ACT_PPP_CONN', { stack });
  }

  async reconnectGponWan(timeoutMs = 60_000): Promise<WanConnection> {
    const { stack } = await this.gponWan();
    await this.operate('ACT_PPP_DISCONN', { stack });
    await this.#awaitStatus(stack, status => status !== CONNECTED_STATUS, timeoutMs);
    await this.operate('ACT_PPP_CONN', { stack });
    return this.#awaitStatus(stack, status => status === CONNECTED_STATUS, timeoutMs);
  }

  async #awaitStatus(stack: string, reached: (status: string) => boolean, timeoutMs: number): Promise<WanConnection> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const connections = await this.listWanConnections();
      const connection = connections.find(candidate => candidate.stack === stack);
      if (connection === undefined) throw new RouterError(`Router reported no WAN connection on stack ${stack}`);
      if (reached(connection.connStatusV4)) return connection;
      if (Date.now() > deadline) throw new RouterError(`WAN connection on stack ${stack} stayed ${connection.connStatusV4} for ${timeoutMs} ms`);
      await new Promise(resolve => setTimeout(resolve, 1_000));
    }
  }

  #unwrap<T>(response: DmResponse<T>): T {
    if (!response.success) {
      throw new RouterError(`Operation on router failed with error code ${response.errorcode}`);
    }
    return response.data;
  }

  async #json<T>(operation: Operation, oid: string, data: Record<string, string>): Promise<DmResponse<T>> {
    const payload = await this.#exchange(operation, oid, data);
    try {
      return JSON.parse(payload) as DmResponse<T>;
    } catch (error) {
      throw new RouterError(`Router returned an unparsable payload for "${oid}"`, { cause: error });
    }
  }

  async #exchange(operation: Operation, oid: string, data: Record<string, string>, isLogin = false): Promise<string> {
    if (this.#signatureHash === '') throw new RouterError('login() must complete before any router request');
    const request = { data: { stack: DEFAULT_STACK, pstack: DEFAULT_STACK, ...data }, operation, oid };
    const ciphertext = aesEncrypt(this.#session, `${JSON.stringify(request)}\r\n`);
    const position = this.#sequence + ciphertext.length;
    const signingMaterial = isLogin
      ? `${aesKeyString(this.#session)}&h=${this.#signatureHash}&s=${position}`
      : `h=${this.#signatureHash}&s=${position}`;
    const sign = rsaRawEncrypt(this.#publicKey, signingMaterial);

    return aesDecrypt(this.#session, await this.#post('/cgi_gdpr?9', `sign=${sign}\r\ndata=${ciphertext}\r\n`));
  }

  async #get(path: string): Promise<string> {
    return this.#accept(await this.#request('GET', path, ''), path);
  }

  async #post(path: string, body: string): Promise<string> {
    return this.#accept(await this.#request('POST', path, body), path);
  }

  #accept(response: HttpResponse, path: string): string {
    this.#storeCookies(response.cookies);
    if (response.status >= 400) throw new RouterError(`Router rejected "${path}" with status ${response.status}`);
    return response.body;
  }

  #storeCookies(cookies: string[]): void {
    for (const cookie of cookies) {
      const pair = cookie.split(';')[0] ?? '';
      const separator = pair.indexOf('=');
      if (separator > 0) this.#cookies.set(pair.slice(0, separator), pair.slice(separator + 1));
    }
  }

  #request(method: 'GET' | 'POST', path: string, body: string): Promise<HttpResponse> {
    const url = new URL(path, this.#baseUrl);
    const headers: Record<string, string> = {
      Accept: 'text/plain, */*; q=0.01',
      'Content-Type': 'text/plain',
      Referer: `${this.#baseUrl}/dashboard/index.html`,
      'X-Requested-With': 'XMLHttpRequest',
      TokenID: this.#token
    };
    if (this.#cookies.size > 0) {
      headers.Cookie = [...this.#cookies].map(([name, value]) => `${name}=${value}`).join('; ');
    }
    const head = [
      `${method} ${url.pathname}${url.search} HTTP/1.1`,
      `Host: ${url.host}`,
      ...Object.entries(headers).map(([name, value]) => `${name}: ${value}`),
      `Content-Length: ${Buffer.byteLength(body)}`,
      'Connection: close',
      '',
      ''
    ].join('\r\n');

    return new Promise((resolve, reject) => {
      const socket = connect({ host: url.hostname, port: Number(url.port || 443), rejectUnauthorized: false }, () => {
        socket.write(head + body);
      });
      const chunks: Buffer[] = [];
      const settle = (): void => resolve(parseHttpResponse(Buffer.concat(chunks)));

      socket.on('data', chunk => chunks.push(chunk as Buffer));
      socket.on('end', settle);
      socket.on('close', settle);
      socket.on('error', error => reject(new RouterError(`Router request to "${path}" failed`, { cause: error })));
      socket.setTimeout(DEFAULT_TIMEOUT_MS, () => {
        socket.destroy();
        reject(new RouterError(`Router request to "${path}" timed out`));
      });
    });
  }
}

function toBase64(value: string): string {
  return Buffer.from(value, 'utf8').toString('base64');
}

function readScriptResult(script: string): number {
  const matches = [...script.matchAll(/\$\.ret\s*=\s*(-?\d+)/g)];
  const lastMatch = matches.at(-1);
  if (!lastMatch) throw new RouterError('Router response carried no result code');
  return Number(lastMatch[1]);
}

function readAssignedString(source: string, name: string): string {
  const match = new RegExp(`var\\s+${name}\\s*=\\s*"([^"]*)"`).exec(source);
  const value = match?.[1];
  if (value === undefined) throw new RouterError(`Router did not provide "${name}"`);
  return value;
}
