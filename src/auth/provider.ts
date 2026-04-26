import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import type { OAuthRegisteredClientsStore } from '@modelcontextprotocol/sdk/server/auth/clients.js';
import {
	InvalidGrantError,
	InvalidTokenError,
	ServerError,
} from '@modelcontextprotocol/sdk/server/auth/errors.js';
import type {
	AuthorizationParams,
	OAuthServerProvider,
} from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type {
	OAuthClientInformationFull,
	OAuthTokens,
} from '@modelcontextprotocol/sdk/shared/auth.js';
import type { Response } from 'express';

const AUTHORIZATION_CODE_TTL_MS = 5 * 60 * 1000;
const ACCESS_TOKEN_TTL_SECONDS = 60 * 60;
const REFRESH_TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000;

export interface PreRegisteredClient {
	clientId: string;
	clientSecret: string;
	redirectUris: string[];
}

export interface InMemoryOAuthProviderOptions {
	client: PreRegisteredClient;
}

interface StoredAuthorizationCode {
	clientId: string;
	redirectUri: string;
	codeChallenge: string;
	scopes: string[];
	expiresAt: number;
}

interface StoredAccessToken {
	clientId: string;
	scopes: string[];
	expiresAt: number;
}

interface StoredRefreshToken {
	clientId: string;
	scopes: string[];
	expiresAt: number;
}

class StaticClientsStore implements OAuthRegisteredClientsStore {
	private readonly client: OAuthClientInformationFull;

	constructor(client: PreRegisteredClient) {
		this.client = {
			client_id: client.clientId,
			client_secret: client.clientSecret,
			redirect_uris: client.redirectUris,
			grant_types: ['authorization_code', 'refresh_token'],
			response_types: ['code'],
			token_endpoint_auth_method: 'client_secret_post',
		};
	}

	async getClient(clientId: string): Promise<OAuthClientInformationFull | undefined> {
		if (!constantTimeEqualString(clientId, this.client.client_id)) {
			return undefined;
		}
		return this.client;
	}
	// registerClient intentionally omitted: Dynamic Client Registration is disabled.
}

export class InMemoryOAuthProvider implements OAuthServerProvider {
	readonly clientsStore: OAuthRegisteredClientsStore;

	private readonly authorizationCodes = new Map<string, StoredAuthorizationCode>();
	private readonly accessTokens = new Map<string, StoredAccessToken>();
	private readonly refreshTokens = new Map<string, StoredRefreshToken>();

	constructor(options: InMemoryOAuthProviderOptions) {
		this.clientsStore = new StaticClientsStore(options.client);
	}

	async authorize(
		client: OAuthClientInformationFull,
		params: AuthorizationParams,
		res: Response,
	): Promise<void> {
		if (!client.redirect_uris.includes(params.redirectUri)) {
			throw new ServerError('Unregistered redirect_uri');
		}

		const code = randomToken();
		this.authorizationCodes.set(code, {
			clientId: client.client_id,
			redirectUri: params.redirectUri,
			codeChallenge: params.codeChallenge,
			scopes: params.scopes ?? [],
			expiresAt: Date.now() + AUTHORIZATION_CODE_TTL_MS,
		});

		const redirect = new URL(params.redirectUri);
		redirect.searchParams.set('code', code);
		if (params.state) {
			redirect.searchParams.set('state', params.state);
		}
		res.redirect(302, redirect.href);
	}

	async challengeForAuthorizationCode(
		client: OAuthClientInformationFull,
		authorizationCode: string,
	): Promise<string> {
		const stored = this.authorizationCodes.get(authorizationCode);
		if (!stored || stored.clientId !== client.client_id) {
			throw new InvalidGrantError('Invalid authorization code');
		}
		if (stored.expiresAt < Date.now()) {
			this.authorizationCodes.delete(authorizationCode);
			throw new InvalidGrantError('Authorization code expired');
		}
		return stored.codeChallenge;
	}

	async exchangeAuthorizationCode(
		client: OAuthClientInformationFull,
		authorizationCode: string,
		_codeVerifier?: string,
		redirectUri?: string,
	): Promise<OAuthTokens> {
		const stored = this.authorizationCodes.get(authorizationCode);
		if (!stored || stored.clientId !== client.client_id) {
			throw new InvalidGrantError('Invalid authorization code');
		}
		// Single-use: consume the code regardless of further validation.
		this.authorizationCodes.delete(authorizationCode);

		if (stored.expiresAt < Date.now()) {
			throw new InvalidGrantError('Authorization code expired');
		}
		if (redirectUri !== undefined && redirectUri !== stored.redirectUri) {
			throw new InvalidGrantError('redirect_uri mismatch');
		}

		return this.issueTokens(client.client_id, stored.scopes);
	}

	async exchangeRefreshToken(
		client: OAuthClientInformationFull,
		refreshToken: string,
		scopes?: string[],
	): Promise<OAuthTokens> {
		const stored = this.refreshTokens.get(refreshToken);
		if (!stored || stored.clientId !== client.client_id) {
			throw new InvalidGrantError('Invalid refresh token');
		}
		if (stored.expiresAt < Date.now()) {
			this.refreshTokens.delete(refreshToken);
			throw new InvalidGrantError('Refresh token expired');
		}

		// Optional scope narrowing: requested scopes must be a subset of the originally granted scopes.
		const granted = new Set(stored.scopes);
		const next = scopes ?? stored.scopes;
		for (const scope of next) {
			if (!granted.has(scope)) {
				throw new InvalidGrantError(`Scope not originally granted: ${scope}`);
			}
		}

		// Rotate refresh token.
		this.refreshTokens.delete(refreshToken);
		return this.issueTokens(client.client_id, next);
	}

	async verifyAccessToken(token: string): Promise<AuthInfo> {
		const stored = this.accessTokens.get(token);
		if (!stored) {
			throw new InvalidTokenError('Unknown access token');
		}
		if (stored.expiresAt < Date.now() / 1000) {
			this.accessTokens.delete(token);
			throw new InvalidTokenError('Access token expired');
		}
		return {
			token,
			clientId: stored.clientId,
			scopes: stored.scopes,
			expiresAt: stored.expiresAt,
		};
	}

	private issueTokens(clientId: string, scopes: string[]): OAuthTokens {
		const accessToken = randomToken();
		const refreshToken = randomToken();
		const expiresAtSeconds = Math.floor(Date.now() / 1000) + ACCESS_TOKEN_TTL_SECONDS;

		this.accessTokens.set(accessToken, {
			clientId,
			scopes,
			expiresAt: expiresAtSeconds,
		});
		this.refreshTokens.set(refreshToken, {
			clientId,
			scopes,
			expiresAt: Date.now() + REFRESH_TOKEN_TTL_MS,
		});

		return {
			access_token: accessToken,
			token_type: 'Bearer',
			expires_in: ACCESS_TOKEN_TTL_SECONDS,
			refresh_token: refreshToken,
			scope: scopes.length > 0 ? scopes.join(' ') : undefined,
		};
	}
}

function randomToken(): string {
	return randomBytes(32).toString('base64url');
}

function constantTimeEqualString(a: string, b: string): boolean {
	const aBuf = Buffer.from(sha256(a));
	const bBuf = Buffer.from(sha256(b));
	return timingSafeEqual(aBuf, bBuf);
}

function sha256(value: string): Buffer {
	return createHash('sha256').update(value).digest();
}
