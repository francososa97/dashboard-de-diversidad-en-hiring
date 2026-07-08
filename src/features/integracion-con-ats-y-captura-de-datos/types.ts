/**
 * E1-T2 — Tipos de dominio para la sincronización periódica de candidatos.
 *
 * Nota: la task pide reusar `src/shared/types/index.ts`, pero ese módulo aún
 * no existe en el repositorio. Para no bloquear la implementación se definen
 * aquí los tipos mínimos necesarios; cuando el shared exista, estos alias
 * deberían re-exportarse desde allí y eliminarse de este archivo.
 */

/** Identificador de tenant (multi-tenant). */
export type TenantId = string;

/** Proveedores de ATS soportados por la integración. */
export type AtsProvider = 'greenhouse' | 'lever' | 'workable' | 'ashby';

/** Tenant con una integración de ATS activa. */
export interface ConnectedTenant {
  readonly tenantId: TenantId;
  readonly provider: AtsProvider;
}

/**
 * Etapa de un candidato dentro del pipeline del ATS (ej. "Screening",
 * "Onsite", "Offer"). Se normaliza a nombre + orden para poder graficar
 * embudos independientes del proveedor.
 */
export interface CandidateStage {
  readonly externalId: string;
  readonly name: string;
  /** Posición de la etapa en el pipeline (0 = primera). */
  readonly order: number;
  /** Momento en que el candidato entró a esta etapa. */
  readonly enteredAt: Date;
}

/** Candidato importado desde el ATS junto con sus etapas. */
export interface Candidate {
  readonly externalId: string;
  readonly tenantId: TenantId;
  readonly fullName: string;
  readonly email: string | null;
  readonly jobExternalId: string;
  readonly appliedAt: Date;
  readonly currentStage: string;
  readonly stages: readonly CandidateStage[];
}

/** Registro de auditoría de una ejecución de sincronización. */
export interface SyncAuditRecord {
  readonly tenantId: TenantId;
  readonly provider: AtsProvider;
  /** Cantidad de candidatos efectivamente sincronizados (upsert). */
  readonly syncedRecords: number;
  /** Timestamp de ejecución del job. */
  readonly executedAt: Date;
  readonly status: 'success' | 'failed';
  /** Mensaje de error si `status === 'failed'`. */
  readonly error?: string;
}

/**
 * Cliente del ATS de un proveedor concreto. La implementación real vive en
 * otro archivo de la épica (E1-T1). Aquí sólo se consume la interfaz.
 */
export interface AtsClient {
  /** Trae todos los candidatos (con sus etapas) del tenant. */
  fetchCandidates(tenantId: TenantId): Promise<readonly Candidate[]>;
}

/** Factory que resuelve el cliente adecuado según el proveedor del tenant. */
export interface AtsClientFactory {
  create(provider: AtsProvider): AtsClient;
}

/** Repositorio de tenants para descubrir cuáles tienen ATS conectado. */
export interface TenantRepository {
  listConnectedTenants(): Promise<readonly ConnectedTenant[]>;
}

/** Persistencia de candidatos. */
export interface CandidateRepository {
  /**
   * Inserta o actualiza los candidatos del tenant.
   * @returns cantidad de registros afectados (creados + actualizados).
   */
  upsertMany(tenantId: TenantId, candidates: readonly Candidate[]): Promise<number>;
}

/** Persistencia de la tabla de auditoría de sincronizaciones. */
export interface SyncAuditRepository {
  record(entry: SyncAuditRecord): Promise<void>;
}

/** Abstracción de reloj para poder testear timestamps deterministamente. */
export interface Clock {
  now(): Date;
}

/** Reloj por defecto basado en el sistema. */
export const systemClock: Clock = {
  now(): Date {
    return new Date();
  },
};

/** Payload de un job que sincroniza un único tenant. */
export interface SyncTenantJobData {
  readonly tenantId: TenantId;
  readonly provider: AtsProvider;
}

/** Payload (vacío) del job repetible que despacha uno por tenant. */
export type DispatchJobData = Record<string, never>;

/** Unión de payloads que puede transportar la cola. */
export type SyncQueueData = SyncTenantJobData | DispatchJobData;

/** Nombres de job usados dentro de la cola de sincronización. */
export const SYNC_JOB_NAMES = {
  /** Job repetible (cada 24h) que abre un job por tenant conectado. */
  dispatch: 'dispatch-sync',
  /** Job que sincroniza un tenant concreto. */
  syncTenant: 'sync-tenant',
} as const;

export type SyncJobName = (typeof SYNC_JOB_NAMES)[keyof typeof SYNC_JOB_NAMES];

/** Nombre de la cola BullMQ. */
export const ATS_SYNC_QUEUE_NAME = 'ats-candidate-sync';

/** Intervalo por defecto entre ejecuciones: 24 horas en milisegundos. */
export const DEFAULT_SYNC_INTERVAL_MS = 24 * 60 * 60 * 1000;
