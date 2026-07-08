/**
 * Tipos de dominio para la integracion OAuth con un ATS.
 * Idealmente estos tipos se reexportarian desde src/shared/types/index.ts;
 * se definen aqui de forma local para que la feature compile de manera autonoma
 * mientras ese barrel no exista.
 */

/** Estado de la conexion de un tenant con su ATS. */
export type ConnectionStatus = 'not_connected' | 'connecting' | 'connected' | 'error';

/** Proveedores de ATS soportados. */
export type AtsProvider = 'greenhouse' | 'lever' | 'workday' | 'ashby';

/** Configuracion OAuth por proveedor. */
export interface OAuthProviderConfig {
  readonly provider: AtsProvider;
  readonly clientId: string;
  readonly clientSecret: string;
  readonly authorizationEndpoint: string;
  readonly tokenEndpoint: string;
  readonly redirectUri: string;
  readonly scopes: readonly string[];
}

/** Token cifrado tal como se persiste (nunca en claro). */
export interface EncryptedToken {
  readonly ciphertext: string; // base64
  readonly iv: string; // base64
  readonly authTag: string; // base64
}

/** Respuesta cruda del token endpoint del ATS. */
export interface OAuthTokenResponse {
  readonly access_token: string;
  readonly token_type: string;
  readonly expires_in?: number;
  readonly refresh_token?: string;
  readonly scope?: string;
}

/** Registro de conexion persistido para un tenant. */
export interface AtsConnection {
  readonly tenantId: string;
  readonly provider: AtsProvider;
  readonly status: ConnectionStatus;
  readonly encryptedToken: EncryptedToken | null;
  readonly connectedAt: string | null; // ISO-8601
  readonly expiresAt: string | null; // ISO-8601
  readonly lastError: string | null;
}

/** Parametros del callback OAuth (query string de la redireccion del ATS). */
export interface OAuthCallbackParams {
  readonly code?: string;
  readonly state?: string;
  readonly error?: string; // p.ej. 'access_denied' cuando el usuario rechaza
  readonly error_description?: string;
}

/** Persistencia de conexiones (implementable con Postgres, DynamoDB, etc.). */
export interface ConnectionRepository {
  get(tenantId: string): Promise<AtsConnection | null>;
  save(connection: AtsConnection): Promise<void>;
}

/** State OAuth firmado, para prevenir CSRF y ligar el callback a un tenant. */
export interface OAuthState {
  readonly tenantId: string;
  readonly provider: AtsProvider;
  readonly nonce: string;
  readonly issuedAt: number; // epoch ms
}

/** Resultado de iniciar el flujo OAuth. */
export interface StartAuthorizationResult {
  readonly authorizationUrl: string;
  readonly state: string;
}
