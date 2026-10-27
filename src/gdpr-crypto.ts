import { constants, createCipheriv, createDecipheriv, createHash, createPublicKey, publicEncrypt, randomBytes } from 'node:crypto';

export interface AesSession {
  key: string;
  iv: string;
}

export interface RsaPublicKey {
  modulusHex: string;
  exponentHex: string;
}

const AES_MATERIAL_BYTES = 8;

export function md5Hex(value: string): string {
  return createHash('md5').update(value, 'utf8').digest('hex');
}

export function createAesSession(): AesSession {
  return {
    key: randomBytes(AES_MATERIAL_BYTES).toString('hex'),
    iv: randomBytes(AES_MATERIAL_BYTES).toString('hex')
  };
}

export function aesKeyString(session: AesSession): string {
  return `key=${session.key}&iv=${session.iv}`;
}

export function aesEncrypt(session: AesSession, plaintext: string): string {
  const cipher = createCipheriv('aes-128-cbc', Buffer.from(session.key, 'utf8'), Buffer.from(session.iv, 'utf8'));
  return Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]).toString('base64');
}

export function aesDecrypt(session: AesSession, ciphertextBase64: string): string {
  const decipher = createDecipheriv('aes-128-cbc', Buffer.from(session.key, 'utf8'), Buffer.from(session.iv, 'utf8'));
  return Buffer.concat([decipher.update(ciphertextBase64, 'base64'), decipher.final()]).toString('utf8');
}

export function rsaRawEncrypt(publicKey: RsaPublicKey, plaintext: string): string {
  const key = createPublicKey({
    key: {
      kty: 'RSA',
      n: Buffer.from(publicKey.modulusHex, 'hex').toString('base64url'),
      e: Buffer.from(publicKey.exponentHex, 'hex').toString('base64url')
    },
    format: 'jwk'
  });
  const blockLength = publicKey.modulusHex.length / 2;
  const plaintextBytes = Buffer.from(plaintext, 'utf8');
  const blocks: string[] = [];

  for (let offset = 0; offset < plaintextBytes.length; offset += blockLength) {
    const block = Buffer.alloc(blockLength);
    plaintextBytes.copy(block, 0, offset, Math.min(offset + blockLength, plaintextBytes.length));
    blocks.push(publicEncrypt({ key, padding: constants.RSA_NO_PADDING }, block).toString('hex'));
  }

  return blocks.join('');
}
