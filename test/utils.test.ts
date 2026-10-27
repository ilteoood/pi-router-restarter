import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { RouterError } from '../src/router-error.ts';
import { readAssignedString, readScriptResult, toBase64 } from '../src/utils.ts';

function assertRouterError(call: () => void, message: RegExp): void {
  assert.throws(call, (error: unknown) => {
    assert.ok(error instanceof RouterError, 'expected a RouterError');
    assert.match(error.message, message);
    return true;
  });
}

describe('toBase64', () => {
  it('encodes the ASCII credentials the login form sends', () => {
    assert.equal(toBase64('admin'), 'YWRtaW4=');
    assert.equal(toBase64('teolino1994!'), 'dGVvbGlubzE5OTQh');
  });

  it('encodes multi-byte characters as UTF-8', () => {
    assert.equal(toBase64('€'), '4oKs');
  });

  it('encodes an empty value to an empty string', () => {
    assert.equal(toBase64(''), '');
  });
});

describe('readScriptResult', () => {
  it('reads the result code of a login script', () => {
    assert.equal(readScriptResult('var token="abc";\n$.ret=0;'), 0);
  });

  it('reads a negative result code ignoring surrounding spaces', () => {
    assert.equal(readScriptResult('$.ret = -1;'), -1);
  });

  it('keeps the last result code of an assignment sequence', () => {
    assert.equal(readScriptResult('$.ret=1;\n$.ret=0;'), 0);
  });

  it('rejects a script carrying no result code', () => {
    assertRouterError(() => readScriptResult('var token="abc";'), /no result code/);
  });
});

describe('readAssignedString', () => {
  it('reads the public key parameters of the GDPR handshake', () => {
    assert.equal(readAssignedString('var nn = "a1b2";\nvar ee = "10001";', 'nn'), 'a1b2');
    assert.equal(readAssignedString('var nn = "a1b2";\nvar ee = "10001";', 'ee'), '10001');
  });

  it('reads an empty assignment', () => {
    assert.equal(readAssignedString('var token="";', 'token'), '');
  });

  it('does not match a longer variable sharing the prefix', () => {
    assertRouterError(() => readAssignedString('var nnOther = "a1b2";', 'nn'), /did not provide "nn"/);
  });

  it('rejects a variable declared with single quotes', () => {
    assertRouterError(() => readAssignedString("var nn = 'a1b2';", 'nn'), /did not provide "nn"/);
  });

  it('rejects a source missing the requested variable', () => {
    assertRouterError(() => readAssignedString('var ee = "10001";', 'nn'), /did not provide "nn"/);
  });
});
