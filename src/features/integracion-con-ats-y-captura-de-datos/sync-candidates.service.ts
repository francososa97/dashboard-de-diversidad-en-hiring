import {
  AtsClient,
  AtsClientFactory,
  Candidate,
  CandidateRepository,
  Clock,
  ConnectedTenant,
  SyncAuditRecord,
  SyncAuditRepository,
  SyncTenantJobData,
  TenantId,
  TenantRepository,
  systemClock,
} from './types';

/** Logger mínimo e inyectable (compatible con pino/winston/console). */
export interface SyncLogger {
  info(message: string, meta?: Record<string, unknown>): void;
  error(message: string, meta?: Record<string, unknown>): void;
}

const noopLogger: SyncLogger = {
  info(): void {
    /* no-op */
  },
  error(): void {
    /* no-op */
  },
};

/** Dependencias del servicio de sincronización (todas inyectables). */
export interface SyncCandidatesDeps {
  readonly tenantRepository: TenantRepository;
  readonly candidateRepository: CandidateRepository;
  readonly auditRepository: SyncAuditRepository;
  readonly atsClientFactory: AtsClientFactory;
  readonly clock?: Clock;
  readonly logger?: SyncLogger;
}

/** Resultado de sincronizar un tenant. */
export interface SyncTenantResult {
  readonly tenantId: TenantId;
  readonly syncedRecords: number;
  readonly executedAt: Date;
  readonly status: 'success' | 'failed';
}

/**
 * Orquesta la importación de candidatos + etapas desde el ATS y registra
 * cada corrida en la tabla de auditoría. No conoce BullMQ: es invocable
 * desde un worker, un endpoint manual o un test.
 */
export class SyncCandidatesService {
  private readonly tenantRepository: TenantRepository;
  private readonly candidateRepository: CandidateRepository;
  private readonly auditRepository: SyncAuditRepository;
  private readonly atsClientFactory: AtsClientFactory;
  private readonly clock: Clock;
  private readonly logger: SyncLogger;

  constructor(deps: SyncCandidatesDeps) {
    this.tenantRepository = deps.tenantRepository;
    this.candidateRepository = deps.candidateRepository;
    this.auditRepository = deps.auditRepository;
    this.atsClientFactory = deps.atsClientFactory;
    this.clock = deps.clock ?? systemClock;
    this.logger = deps.logger ?? noopLogger;
  }

  /** Tenants con ATS conectado; el dispatcher abre un job por cada uno. */
  listConnectedTenants(): Promise<readonly ConnectedTenant[]> {
    return this.tenantRepository.listConnectedTenants();
  }

  /**
   * Importa los candidatos (y sus etapas) de un tenant y persiste el
   * registro de auditoría con la cantidad sincronizada y el timestamp.
   *
   * En caso de error registra una fila de auditoría con `status: 'failed'`
   * y re-lanza para que BullMQ aplique la política de reintentos.
   */
  async syncTenant(job: SyncTenantJobData): Promise<SyncTenantResult> {
    const { tenantId, provider } = job;

    try {
      const client: AtsClient = this.atsClientFactory.create(provider);
      const candidates: readonly Candidate[] = await client.fetchCandidates(tenantId);
      const syncedRecords: number = await this.candidateRepository.upsertMany(
        tenantId,
        candidates,
      );
      const executedAt: Date = this.clock.now();

      const record: SyncAuditRecord = {
        tenantId,
        provider,
        syncedRecords,
        executedAt,
        status: 'success',
      };
      await this.auditRepository.record(record);

      this.logger.info('ATS candidate sync completed', {
        tenantId,
        provider,
        syncedRecords,
        executedAt: executedAt.toISOString(),
      });

      return { tenantId, syncedRecords, executedAt, status: 'success' };
    } catch (err: unknown) {
      const executedAt: Date = this.clock.now();
      const message: string = err instanceof Error ? err.message : String(err);

      const failure: SyncAuditRecord = {
        tenantId,
        provider,
        syncedRecords: 0,
        executedAt,
        status: 'failed',
        error: message,
      };
      await this.auditRepository.record(failure);

      this.logger.error('ATS candidate sync failed', {
        tenantId,
        provider,
        error: message,
      });

      throw err instanceof Error ? err : new Error(message);
    }
  }
}
