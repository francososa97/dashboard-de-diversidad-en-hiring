import {
  Job,
  Queue,
  Worker,
  type ConnectionOptions,
  type JobsOptions,
} from 'bullmq';
import {
  ATS_SYNC_QUEUE_NAME,
  ConnectedTenant,
  DEFAULT_SYNC_INTERVAL_MS,
  SYNC_JOB_NAMES,
  SyncQueueData,
  SyncTenantJobData,
} from './types';
import { SyncCandidatesService, SyncTenantResult } from './sync-candidates.service';

/** ID estático del job repetible para evitar duplicar schedulers. */
const DISPATCH_JOB_ID = 'ats-sync-dispatch';

/** Opciones por defecto aplicadas a cada job de la cola. */
const DEFAULT_JOB_OPTIONS: JobsOptions = {
  attempts: 3,
  backoff: { type: 'exponential', delay: 60_000 },
  removeOnComplete: 1_000,
  removeOnFail: 5_000,
};

/** Crea (sin arrancar) la cola de sincronización de candidatos. */
export function createSyncQueue(connection: ConnectionOptions): Queue<SyncQueueData> {
  return new Queue<SyncQueueData>(ATS_SYNC_QUEUE_NAME, {
    connection,
    defaultJobOptions: DEFAULT_JOB_OPTIONS,
  });
}

/**
 * Registra el job repetible que corre cada `intervalMs` (24h por defecto) y
 * cuya única misión es despachar un job `sync-tenant` por cada tenant con
 * ATS conectado. Idempotente: reutiliza `DISPATCH_JOB_ID`.
 */
export async function registerSyncScheduler(
  queue: Queue<SyncQueueData>,
  intervalMs: number = DEFAULT_SYNC_INTERVAL_MS,
): Promise<void> {
  await queue.add(
    SYNC_JOB_NAMES.dispatch,
    {},
    {
      repeat: { every: intervalMs },
      jobId: DISPATCH_JOB_ID,
      removeOnComplete: true,
      removeOnFail: true,
    },
  );
}

/** Encola un job `sync-tenant` por cada tenant conectado. Devuelve el total. */
async function dispatchTenantJobs(
  queue: Queue<SyncQueueData>,
  service: SyncCandidatesService,
): Promise<number> {
  const tenants: readonly ConnectedTenant[] = await service.listConnectedTenants();

  if (tenants.length === 0) {
    return 0;
  }

  await queue.addBulk(
    tenants.map((tenant: ConnectedTenant) => ({
      name: SYNC_JOB_NAMES.syncTenant,
      data: {
        tenantId: tenant.tenantId,
        provider: tenant.provider,
      } satisfies SyncTenantJobData,
    })),
  );

  return tenants.length;
}

/**
 * Crea el worker que procesa la cola. Maneja dos tipos de job:
 *  - `dispatch-sync`: fan-out, encola un `sync-tenant` por tenant.
 *  - `sync-tenant`: delega en el servicio la importación + auditoría.
 *
 * Se pasa la `queue` porque el branch de dispatch necesita encolar jobs.
 */
export function createSyncWorker(
  service: SyncCandidatesService,
  queue: Queue<SyncQueueData>,
  connection: ConnectionOptions,
  concurrency: number = 4,
): Worker<SyncQueueData, SyncTenantResult | number> {
  return new Worker<SyncQueueData, SyncTenantResult | number>(
    ATS_SYNC_QUEUE_NAME,
    async (job: Job<SyncQueueData, SyncTenantResult | number>): Promise<SyncTenantResult | number> => {
      if (job.name === SYNC_JOB_NAMES.dispatch) {
        return dispatchTenantJobs(queue, service);
      }

      if (job.name === SYNC_JOB_NAMES.syncTenant) {
        return service.syncTenant(job.data as SyncTenantJobData);
      }

      throw new Error(`Unknown job name: ${job.name}`);
    },
    { connection, concurrency },
  );
}

/** Handles devueltos por el bootstrap para poder cerrarlos ordenadamente. */
export interface AtsSyncRuntime {
  readonly queue: Queue<SyncQueueData>;
  readonly worker: Worker<SyncQueueData, SyncTenantResult | number>;
  close(): Promise<void>;
}

/**
 * Cablea todo de una: crea la cola, registra el scheduler de 24h y levanta
 * el worker. Pensado para invocarse una vez al arrancar el proceso worker.
 */
export async function startAtsSync(
  service: SyncCandidatesService,
  connection: ConnectionOptions,
  options: { intervalMs?: number; concurrency?: number } = {},
): Promise<AtsSyncRuntime> {
  const queue: Queue<SyncQueueData> = createSyncQueue(connection);
  await registerSyncScheduler(queue, options.intervalMs ?? DEFAULT_SYNC_INTERVAL_MS);
  const worker: Worker<SyncQueueData, SyncTenantResult | number> = createSyncWorker(
    service,
    queue,
    connection,
    options.concurrency ?? 4,
  );

  return {
    queue,
    worker,
    async close(): Promise<void> {
      await worker.close();
      await queue.close();
    },
  };
}
