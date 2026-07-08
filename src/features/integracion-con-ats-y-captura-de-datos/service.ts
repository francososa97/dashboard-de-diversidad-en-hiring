import { FieldEncryptionService } from './field-crypto';
import type {
  CandidateId,
  DemographicField,
  EncryptedDemographicRepository,
  EncryptedDemographicRow,
  IngestionResult,
  TenantId,
} from './types';

/**
 * Servicio de ingesta de campos demográficos desde el ATS.
 *
 * Cumple E1-T3: cada campo demográfico importado se cifra (AES-256-GCM con DEK por tenant
 * envuelta por KMS) ANTES de tocar la base de datos. La columna solo almacena el sobre
 * base64, de modo que una query directa a la columna, sin la key del tenant en el KMS,
 * jamás devuelve el valor en texto plano.
 */
export class DemographicIngestionService {
  public constructor(
    private readonly encryption: FieldEncryptionService,
    private readonly repository: EncryptedDemographicRepository,
  ) {}

  /**
   * Ingesta y persiste de forma cifrada todos los campos demográficos de un candidato.
   * Campos con valor vacío/whitespace se ignoran (no se cifra ruido).
   */
  public async ingest(
    tenantId: TenantId,
    candidateId: CandidateId,
    fields: readonly DemographicField[],
  ): Promise<IngestionResult> {
    this.assertIdentifier(tenantId, 'tenantId');
    this.assertIdentifier(candidateId, 'candidateId');

    const rows = await this.encryptFields(tenantId, candidateId, fields);
    for (const row of rows) {
      await this.repository.upsert(row);
    }

    return {
      tenantId,
      candidateId,
      encryptedFields: rows.length,
    };
  }

  private async encryptFields(
    tenantId: TenantId,
    candidateId: CandidateId,
    fields: readonly DemographicField[],
  ): Promise<EncryptedDemographicRow[]> {
    const rows: EncryptedDemographicRow[] = [];
    for (const field of fields) {
      const value = field.value.trim();
      if (value.length === 0) {
        continue;
      }
      const encrypted = await this.encryption.encrypt(tenantId, value);
      rows.push({
        tenantId,
        candidateId,
        fieldName: field.name,
        ciphertext: encrypted.ciphertext,
        keyVersion: encrypted.keyVersion,
        algorithm: encrypted.algorithm,
      });
    }
    return rows;
  }

  private assertIdentifier(value: string, label: string): void {
    if (value.trim().length === 0) {
      throw new Error(`${label} es obligatorio`);
    }
  }
}
