import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto';
import type {
  EncryptedValue,
  GeneratedDataKey,
  KmsProvider,
  TenantId,
  TenantKeyRecord,
  TenantKeyStore,
} from './types';

const ALGORITHM = 'aes-256-gcm' as const;
const ENVELOPE_VERSION = 1;
const KEY_LENGTH = 32; // 256 bits
const IV_LENGTH = 12; // 96 bits, recomendado para GCM
const TAG_LENGTH = 16; // 128 bits

/**
 * Cifrado a nivel de campo mediante envelope encryption.
 *
 * Modelo: cada tenant tiene una Data Encryption Key (DEK) de 256 bits que se persiste
 * SIEMPRE envuelta (cifrada) por el KEK del tenant en el KMS. Al cifrar un valor:
 *   1. Se resuelve/genera la DEK del tenant (desenvolviéndola vía KMS).
 *   2. Se cifra el valor con AES-256-GCM usando un IV aleatorio por operación.
 *   3. Se serializa el sobre: version | iv | authTag | ciphertext (base64).
 *
 * Una query directa a la columna solo ve el sobre base64: sin acceso al KMS del tenant
 * la DEK no puede desenvolverse y el valor permanece ilegible. Equivalente conceptual a
 * pgcrypto pgp_sym_encrypt, pero con gestión de claves delegada al KMS.
 */
export class FieldEncryptionService {
  public constructor(
    private readonly kms: KmsProvider,
    private readonly keyStore: TenantKeyStore,
  ) {}

  public async encrypt(tenantId: TenantId, plaintext: string): Promise<EncryptedValue> {
    const { key, keyVersion } = await this.resolveDataKey(tenantId);
    try {
      const iv = randomBytes(IV_LENGTH);
      const cipher = createCipheriv(ALGORITHM, key, iv, { authTagLength: TAG_LENGTH });
      const encrypted = Buffer.concat([
        cipher.update(plaintext, 'utf8'),
        cipher.final(),
      ]);
      const authTag = cipher.getAuthTag();
      const envelope = Buffer.concat([
        Buffer.from([ENVELOPE_VERSION]),
        iv,
        authTag,
        encrypted,
      ]);
      return {
        ciphertext: envelope.toString('base64'),
        keyVersion,
        algorithm: 'AES-256-GCM',
      };
    } finally {
      key.fill(0); // no dejar la DEK en memoria más de lo necesario
    }
  }

  public async decrypt(tenantId: TenantId, ciphertext: string): Promise<string> {
    const record = await this.keyStore.getActiveKey(tenantId);
    if (record === null) {
      throw new Error(`No existe clave activa para el tenant ${tenantId}`);
    }
    const envelope = Buffer.from(ciphertext, 'base64');
    if (envelope.length < 1 + IV_LENGTH + TAG_LENGTH) {
      throw new Error('Sobre cifrado inválido: longitud insuficiente');
    }
    if (envelope[0] !== ENVELOPE_VERSION) {
      throw new Error(`Versión de sobre no soportada: ${String(envelope[0])}`);
    }
    const iv = envelope.subarray(1, 1 + IV_LENGTH);
    const authTag = envelope.subarray(1 + IV_LENGTH, 1 + IV_LENGTH + TAG_LENGTH);
    const data = envelope.subarray(1 + IV_LENGTH + TAG_LENGTH);

    const key = await this.kms.decryptDataKey(tenantId, record.encryptedDataKey);
    try {
      const decipher = createDecipheriv(ALGORITHM, key, iv, { authTagLength: TAG_LENGTH });
      decipher.setAuthTag(authTag);
      const decrypted = Buffer.concat([decipher.update(data), decipher.final()]);
      return decrypted.toString('utf8');
    } finally {
      key.fill(0);
    }
  }

  private async resolveDataKey(
    tenantId: TenantId,
  ): Promise<{ key: Buffer; keyVersion: number }> {
    const existing = await this.keyStore.getActiveKey(tenantId);
    if (existing !== null) {
      const key = await this.kms.decryptDataKey(tenantId, existing.encryptedDataKey);
      this.assertKeyLength(key);
      return { key, keyVersion: existing.keyVersion };
    }
    const generated = await this.kms.generateDataKey(tenantId);
    this.assertKeyLength(generated.plaintextKey);
    const record: TenantKeyRecord = {
      tenantId,
      encryptedDataKey: generated.encryptedKey,
      keyVersion: 1,
    };
    await this.keyStore.saveKey(record);
    return { key: generated.plaintextKey, keyVersion: record.keyVersion };
  }

  private assertKeyLength(key: Buffer): void {
    if (key.length !== KEY_LENGTH) {
      throw new Error(`DEK con longitud inválida: se esperaban ${KEY_LENGTH} bytes`);
    }
  }
}

/**
 * Implementación de KmsProvider basada en un KEK maestro local (env var), útil para
 * desarrollo, tests y despliegues sin un KMS gestionado. En producción se sustituye por
 * un adaptador de AWS KMS / GCP KMS que implemente la misma interfaz.
 *
 * El KEK maestro se combina con el tenantId (como AAD) para aislar criptográficamente a
 * cada tenant: una DEK envuelta para el tenant A no puede desenvolverse como tenant B.
 */
export class LocalKmsProvider implements KmsProvider {
  private static readonly WRAP_ALGORITHM = 'aes-256-gcm' as const;
  private static readonly WRAP_IV_LENGTH = 12;
  private static readonly WRAP_TAG_LENGTH = 16;

  private readonly masterKey: Buffer;

  public constructor(masterKeyBase64: string) {
    const key = Buffer.from(masterKeyBase64, 'base64');
    if (key.length !== KEY_LENGTH) {
      throw new Error('El KEK maestro debe ser 32 bytes (base64 de 256 bits)');
    }
    this.masterKey = key;
  }

  public static fromEnv(env: NodeJS.ProcessEnv = process.env): LocalKmsProvider {
    const raw = env.DEMOGRAPHIC_MASTER_KEK;
    if (raw === undefined || raw.length === 0) {
      throw new Error('Falta la variable de entorno DEMOGRAPHIC_MASTER_KEK');
    }
    return new LocalKmsProvider(raw);
  }

  public generateDataKey(tenantId: TenantId): Promise<GeneratedDataKey> {
    const plaintextKey = randomBytes(KEY_LENGTH);
    const encryptedKey = this.wrap(tenantId, plaintextKey);
    return Promise.resolve({ plaintextKey, encryptedKey });
  }

  public decryptDataKey(tenantId: TenantId, encryptedKey: Buffer): Promise<Buffer> {
    return Promise.resolve(this.unwrap(tenantId, encryptedKey));
  }

  private wrap(tenantId: TenantId, dek: Buffer): Buffer {
    const iv = randomBytes(LocalKmsProvider.WRAP_IV_LENGTH);
    const cipher = createCipheriv(LocalKmsProvider.WRAP_ALGORITHM, this.masterKey, iv, {
      authTagLength: LocalKmsProvider.WRAP_TAG_LENGTH,
    });
    cipher.setAAD(Buffer.from(tenantId, 'utf8'));
    const wrapped = Buffer.concat([cipher.update(dek), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([iv, tag, wrapped]);
  }

  private unwrap(tenantId: TenantId, encryptedKey: Buffer): Buffer {
    const ivEnd = LocalKmsProvider.WRAP_IV_LENGTH;
    const tagEnd = ivEnd + LocalKmsProvider.WRAP_TAG_LENGTH;
    if (encryptedKey.length <= tagEnd) {
      throw new Error('DEK envuelta inválida');
    }
    const iv = encryptedKey.subarray(0, ivEnd);
    const tag = encryptedKey.subarray(ivEnd, tagEnd);
    const data = encryptedKey.subarray(tagEnd);
    const decipher = createDecipheriv(LocalKmsProvider.WRAP_ALGORITHM, this.masterKey, iv, {
      authTagLength: LocalKmsProvider.WRAP_TAG_LENGTH,
    });
    decipher.setAAD(Buffer.from(tenantId, 'utf8'));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(data), decipher.final()]);
  }
}

/** Utilidad de comparación en tiempo constante, reutilizable por consumidores. */
export function constantTimeEquals(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) {
    return false;
  }
  return timingSafeEqual(a, b);
}
