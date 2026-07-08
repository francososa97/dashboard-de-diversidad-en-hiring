// Tipos de dominio para la ingesta cifrada de campos demográficos provenientes del ATS.
// Nota: en este repositorio no existe src/shared/types/index.ts todavía, por lo que los
// tipos compartidos relevantes se definen aquí de forma explícita para mantener el módulo
// autocontenido y en TypeScript strict (sin `any`).

export type TenantId = string;
export type CandidateId = string;

/** Nombres de campos demográficos sensibles capturados desde el ATS. */
export type DemographicFieldName =
  | 'gender'
  | 'ethnicity'
  | 'disabilityStatus'
  | 'veteranStatus'
  | 'age'
  | 'sexualOrientation';

export type FieldAlgorithm = 'AES-256-GCM';

/** Campo demográfico en texto plano tal como llega desde el ATS. */
export interface DemographicField {
  readonly name: DemographicFieldName;
  readonly value: string;
}

/** Resultado del cifrado de un valor individual. */
export interface EncryptedValue {
  /** Sobre (envelope) en base64: version(1B) + iv(12B) + authTag(16B) + ciphertext. */
  readonly ciphertext: string;
  readonly keyVersion: number;
  readonly algorithm: FieldAlgorithm;
}

/** Clave de datos (DEK) generada por el KMS, en claro y envuelta por el KEK del tenant. */
export interface GeneratedDataKey {
  readonly plaintextKey: Buffer;
  readonly encryptedKey: Buffer;
}

/**
 * Proveedor de KMS. Abstrae AWS KMS / GCP KMS / Vault. Cada tenant tiene su propio
 * Key Encryption Key (KEK); las DEK se generan y desenvuelven contra ese KEK, de modo
 * que sin el KMS del tenant no es posible recuperar el texto plano.
 */
export interface KmsProvider {
  generateDataKey(tenantId: TenantId): Promise<GeneratedDataKey>;
  decryptDataKey(tenantId: TenantId, encryptedKey: Buffer): Promise<Buffer>;
}

/** Registro persistido de la DEK envuelta de un tenant. */
export interface TenantKeyRecord {
  readonly tenantId: TenantId;
  readonly encryptedDataKey: Buffer;
  readonly keyVersion: number;
}

/** Almacén de las DEK envueltas por tenant (nunca guarda claves en claro). */
export interface TenantKeyStore {
  getActiveKey(tenantId: TenantId): Promise<TenantKeyRecord | null>;
  saveKey(record: TenantKeyRecord): Promise<void>;
}

/** Fila cifrada lista para persistir en la columna demográfica de Postgres. */
export interface EncryptedDemographicRow {
  readonly tenantId: TenantId;
  readonly candidateId: CandidateId;
  readonly fieldName: DemographicFieldName;
  readonly ciphertext: string;
  readonly keyVersion: number;
  readonly algorithm: FieldAlgorithm;
}

/** Repositorio de persistencia de campos demográficos cifrados. */
export interface EncryptedDemographicRepository {
  upsert(row: EncryptedDemographicRow): Promise<void>;
}

export interface IngestionResult {
  readonly tenantId: TenantId;
  readonly candidateId: CandidateId;
  readonly encryptedFields: number;
}
