import assert from 'node:assert/strict';
import { constants, generateKeyPairSync, privateDecrypt } from 'node:crypto';
import { test } from 'node:test';

import { aesDecrypt, aesEncrypt, createAesSession, md5Hex, rsaRawEncrypt } from '../src/gdpr-crypto.ts';

test('md5Hex matches RFC 1321', () => {
  assert.equal(md5Hex(''), 'd41d8cd98f00b204e9800998ecf8427e');
  assert.equal(md5Hex('abc'), '900150983cd24fb0d6963f7d28e17f72');
});

test('aes session round-trips CBC payloads', () => {
  const session = createAesSession();
  const payload = `${JSON.stringify({ operation: 'go', oid: 'DEV2_GPON', data: {} })}\r\n`;

  assert.equal(aesDecrypt(session, aesEncrypt(session, payload)), payload);
});

test('rsaRawEncrypt produces zero-padded raw blocks the router private key can open', () => {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 512 });
  const key = publicKey.export({ format: 'jwk' });

  const plaintext = 'key=0123456789abcdef&iv=fedcba9876543210&h=900150983cd24fb0d6963f7d28e17f72&s=800855428';
  const encrypted = rsaRawEncrypt({ modulusHex: Buffer.from(key.n as string, 'base64url').toString('hex'), exponentHex: Buffer.from(key.e as string, 'base64url').toString('hex') }, plaintext);

  assert.equal(encrypted.length % 128, 0);
  assert.ok(encrypted.length > 128, 'payload longer than one block must be split into several blocks');

  const decryptedBlocks = [];
  for (let offset = 0; offset < encrypted.length; offset += 128) {
    decryptedBlocks.push(privateDecrypt({ key: privateKey, padding: constants.RSA_NO_PADDING }, Buffer.from(encrypted.slice(offset, offset + 128), 'hex')));
  }

  assert.equal(Buffer.concat(decryptedBlocks).toString('utf8').replace(/\0+$/, ''), plaintext);
});
