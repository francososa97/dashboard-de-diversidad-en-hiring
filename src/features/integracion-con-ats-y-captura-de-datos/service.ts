import { encryptToken, generateNonce, signState, verifyState } from './crypto.js';
import type {
  AtsConnection,
  ConnectionRepository,
  OAuthCallbackParams,
  OAuthProviderConfig,
  OAuthState,
  OAuthTokenResponse,
  StartAuthorizationResult,
} from './types.js';

/** Ventana de validez del state OAuth (10 minutos). */
const STATE_TTL_MS = 10 * 60 * 1000;

/** Presupuesto maximo para el intercambio de codigo por token (AC: < 5s). */
const TOKEN_EXCHANGE_TIMEOUT_MS = 5000;

export interface AtsOAuthServiceDeps {
  readonly repository: ConnectionRepository;
  readonly config: OAuthProviderConfig;
  /** Clave base64 de 32 bytes para cifrado de token y firma de state. */
  readonly encryptionKey: string;
  /** Inyectable para tests; por defecto el fetch global de Node >= 18. */
  readonly fetchFn?: typeof fetch;
  /** Inyectable para tests; por defecto Date.now. */
  readonly now?: () => number;
}

/** Se lanza internamente cuando el usuario rechaza el consentimiento. */
export class OAuthDeniedError extends Error {
  constructor(reason: string) {
    super(`El usuario rechazo la autorizacion OAuth: ${reason}`);
    this.name = 'OAuthDeniedError';
  }
}

/**
 * Servicio que implementa el flujo OAuth (authorization code) contra un ATS.
 * Persiste el token cifrado y mantiene el estado de conexion del tenant.
 */
export class AtsOAuthService {
  private readonly repository: ConnectionRepository;
  private readonly config: OAuthProviderConfig;
  private readonly encryptionKey: string;
  private readonly fetchFn: typeof fetch;
  private readonly now: () => number;

  constructor(deps: AtsOAuthServiceDeps) {
    this.repository = deps.repository;
    this.config = deps.config;
    this.encryptionKey = deps.encryptionKey;
    this.fetchFn = deps.fetchFn ?? fetch;
    this.now = deps.now ?? Date.now;
  }

  /**
   * Paso 1: genera la URL de autorizacion a la que se redirige al admin.
   * Marca la conexion del tenant como 'connecting'.
   */
  async startAuthorization(tenantId: string): Promise<StartAuthorizationResult> {
    const state: OAuthState = {
      tenantId,
      provider: this.config.provider,
      nonce: generateNonce(),
      issuedAt: this.now(),
    };
    const signedState = signState(state, this.encryptionKey);

    const url = new URL(this.config.authorizationEndpoint);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('client_id', this.config.clientId);
    url.searchParams.set('redirect_uri', this.config.redirectUri);
    url.searchParams.set('scope', this.config.scopes.join(' '));
    url.searchParams.set('state', signedState);

    await this.repository.save({
      tenantId,
      provider: this.config.provider,
      status: 'connecting',
      encryptedToken: null,
      connectedAt: null,
      expiresAt: null,
      lastError: null,
    });

    return { authorizationUrl: url.toString(), state: signedState };
  }

  /**
   * Paso 2: procesa el callback del ATS.
   * - Si el usuario rechazo -> status 'not_connected', sin token.
   * - Si autorizo -> intercambia el codigo, cifra y guarda el token, status 'connected'.
   * - Si falla el intercambio -> status 'error', sin token.
   */
  async handleCallback(params: OAuthCallbackParams): Promise<AtsConnection> {
    if (!params.state) {
      throw new Error('Falta el parametro state en el callback OAuth');
    }
    const state = verifyState(params.state, this.encryptionKey);
    if (this.now() - state.issuedAt > STATE_TTL_MS) {
      throw new Error('El state OAuth expiro; reinicia el flujo de conexion');
    }

    // El usuario rechazo la autorizacion: estado not_connected y no se guarda token.
    if (params.error) {
      const connection: AtsConnection = {
        tenantId: state.tenantId,
        provider: state.provider,
        status: 'not_connected',
        encryptedToken: null,
        connectedAt: null,
        expiresAt: null,
        lastError: params.error_description ?? params.error,
      };
      await this.repository.save(connection);
      return connection;
    }

    if (!params.code) {
      throw new Error('El callback no incluye code ni error');
    }

    try {
      const token = await this.exchangeCodeForToken(params.code);
      const encryptedToken = encryptToken(token.access_token, this.encryptionKey);
      const nowMs = this.now();
      const connection: AtsConnection = {
        tenantId: state.tenantId,
        provider: state.provider,
        status: 'connected',
        encryptedToken,
        connectedAt: new Date(nowMs).toISOString(),
        expiresAt:
          typeof token.expires_in === 'number'
            ? new Date(nowMs + token.expires_in * 1000).toISOString()
            : null,
        lastError: null,
      };
      await this.repository.save(connection);
      return connection;
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Error desconocido';
      const connection: AtsConnection = {
        tenantId: state.tenantId,
        provider: state.provider,
        status: 'error',
        encryptedToken: null,
        connectedAt: null,
        expiresAt: null,
        lastError: message,
      };
      await this.repository.save(connection);
      return connection;
    }
  }

  /** Devuelve el estado de conexion actual de un tenant. */
  async getConnection(tenantId: string): Promise<AtsConnection | null> {
    return this.repository.get(tenantId);
  }

  /** Intercambia el authorization code por un access token, con timeout de 5s. */
  private async exchangeCodeForToken(code: string): Promise<OAuthTokenResponse> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), TOKEN_EXCHANGE_TIMEOUT_MS);
    try {
      const body = new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret,
        redirect_uri: this.config.redirectUri,
      });
      const response = await this.fetchFn(this.config.tokenEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Accept: 'application/json',
        },
        body: body.toString(),
        signal: controller.signal,
      });
      if (!response.ok) {
        const detail = await response.text();
        throw new Error(`Token endpoint respondio ${response.status}: ${detail.slice(0, 500)}`);
      }
      const json = (await response.json()) as OAuthTokenResponse;
      if (!json.access_token) {
        throw new Error('La respuesta del token endpoint no contiene access_token');
      }
      return json;
    } catch (err) {
      if (err instanceof Error && err.name === 'AbortError') {
        throw new Error('El intercambio de token supero el limite de 5s');
      }
      throw err;
    } finally {
      clearTimeout(timeout);
    }
  }
}
