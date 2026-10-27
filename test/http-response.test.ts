import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { parseHttpResponse } from '../src/http-response.ts';

describe('parseHttpResponse', () => {
  it('reads a chunked response with headers and cookies', () => {
    const raw = Buffer.from(
      'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nSet-Cookie: JSESSIONID=abc123; Path=/; HttpOnly\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nQUJD\r\n0\r\n\r\n',
      'latin1'
    );

    assert.deepEqual(parseHttpResponse(raw), { status: 200, body: 'QUJD', cookies: ['JSESSIONID=abc123; Path=/; HttpOnly'] });
  });

  it('reads a chunked body that arrives without a status line', () => {
    const raw = Buffer.from('4\r\nQQ==\r\n0\r\n\r\n', 'latin1');

    assert.deepEqual(parseHttpResponse(raw), { status: 0, body: 'QQ==', cookies: [] });
  });

  it('joins several chunks of the same body', () => {
    const raw = Buffer.from('HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nQUJDREU=', 'latin1');

    assert.deepEqual(parseHttpResponse(raw), { status: 200, body: 'QUJDREU=', cookies: [] });
  });

  it('keeps an unframed body that is not chunked', () => {
    const raw = Buffer.from('<html>406 Not Acceptable</html>', 'latin1');

    assert.deepEqual(parseHttpResponse(raw), { status: 0, body: '<html>406 Not Acceptable</html>', cookies: [] });
  });
});
