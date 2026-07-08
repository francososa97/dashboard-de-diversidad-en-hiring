import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto';
import type { EncryptedToken, OAuthState } from './types.js';

const ALGORITHM = 'aes-256-gcm';
const IV_BYTES = 12;
const KEY_BYTES = 32;

function decodeKey(base64Key: string): Buffer {
  const key = Buffer.from(base64Key, 'base64');
  if (key.length !== KEY_BYTES) {
    throw new Error(`La clave de cifrado debe ser de ${KEY_BYTES} bytes (256 bits) en base64`);
  }
  return key;
}

/** Cifra un token de acceso con AES-256-GCM. */
export function encryptToken(plaintext: string, base64Key: string): EncryptedToken {
  const key = decodeKey(base64Key);
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(ALGORITHM, key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return {
    ciphertext: ciphertext.toString('base64'),
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
  };
}

/** Descifra un token previamente cifrado con encryptToken. */
export function decryptToken(token: EncryptedToken, base64Key: string): string {
  const key = decodeKey(base64Key);
  const decipher = createDecipheriv(ALGORITHM, key, Buffer.from(token.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(token.authTag, 'base64'));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(token.ciphertext, 'base64')),
    decipher.final(),
  ]);
  return plaintext.toString('utf8');
}

/** Serializa y firma el state OAuth (HMAC-SHA256) para transportarlo en la URL. */
export function signState(state: OAuthState, base64Key: string): string {
  const payload = Buffer.from(JSON.stringify(state), 'utf8').toString('base64url');
  const signature = createHmac('sha256', decodeKey(base64Key)).update(payload).digest('base64url');
  return `${payload}.${signature}`;
}

/** Verifica y deserializa el state OAuth. Lanza si la firma no coincide. */
export function verifyState(signed: string, base64Key: string): OAuthState {
  const parts = signed.split('.');
  const payload = parts[0];
  const signature = parts[1];
  if (!payload || !signature || parts.length !== 2) {
    throw new Error('State OAuth malformado');
  }
  const expected = createHmac('sha256', decodeKey(base64Key)).update(payload).digest('base64url');
  const sigBuf = Buffer.from(signature);
  const expBuf = Buffer.from(expected);
  if (sigBuf.length !== expBuf.length || !timingSafeEqual(sigBuf, expBuf)) {
    throw new Error('Firma de state OAuth invalida (posible CSRF)');
  }
  return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as OAuthState;
}

/** Genera un nonce aleatorio url-safe para el state. */
export function generateNonce(): string {
  return randomBytes(16).toString('base64url');
}
