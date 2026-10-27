export interface HttpResponse {
  status: number;
  body: string;
  cookies: string[];
}

const HEADER_END = '\r\n\r\n';

export function parseHttpResponse(raw: Buffer): HttpResponse {
  const text = raw.toString('latin1');
  const headerEnd = text.indexOf(HEADER_END);

  if (!text.startsWith('HTTP/') || headerEnd < 0) {
    return { status: 0, body: decodeChunkedBody(text) ?? text, cookies: [] };
  }

  const headerLines = text.slice(0, headerEnd).split('\r\n');
  const status = Number(headerLines[0]?.split(' ')[1] ?? 0);
  const cookies: string[] = [];
  for (const line of headerLines) {
    if (line.toLowerCase().startsWith('set-cookie:')) cookies.push(line.slice('set-cookie:'.length).trim());
  }
  const body = text.slice(headerEnd + HEADER_END.length);
  const isChunked = headerLines.some(line => /^transfer-encoding:\s*chunked/i.test(line));

  return { status, body: isChunked ? decodeChunkedBody(body) ?? body : body, cookies };
}

function decodeChunkedBody(body: string): string | undefined {
  const parts: string[] = [];
  let remainder = body;

  for (;;) {
    const sizeLineEnd = remainder.indexOf('\r\n');
    if (sizeLineEnd < 0) return undefined;
    const size = Number.parseInt(remainder.slice(0, sizeLineEnd), 16);
    if (!Number.isInteger(size) || size < 0) return undefined;

    remainder = remainder.slice(sizeLineEnd + 2);
    if (size === 0) return parts.join('');
    if (remainder.length < size + 2) return undefined;

    parts.push(remainder.slice(0, size));
    remainder = remainder.slice(size + 2);
  }
}
