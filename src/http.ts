import { metadataHandler } from '@modelcontextprotocol/sdk/server/auth/handlers/metadata.js';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import {
	createOAuthMetadata,
	mcpAuthRouter,
} from '@modelcontextprotocol/sdk/server/auth/router.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import express, { type Request, type Response } from 'express';

import { InMemoryOAuthProvider, type PreRegisteredClient } from './auth/provider.js';
import { createMcpServer } from './server.js';

export interface HttpServerConfig {
	port: number;
	host: string;
	publicBaseUrl: URL;
	mcpPath: string;
	client: PreRegisteredClient;
	allowDynamicRegistration: boolean;
}

export function loadHttpConfigFromEnv(): HttpServerConfig {
	const portRaw = process.env.PORT ?? '3000';
	const port = Number.parseInt(portRaw, 10);
	if (!Number.isFinite(port) || port <= 0) {
		throw new Error(`Invalid PORT: ${portRaw}`);
	}

	const host = process.env.HOST ?? '0.0.0.0';
	// Resolution order for the public base URL:
	//   1. MCP_BASE_URL — explicit override (any environment).
	//   2. RENDER_EXTERNAL_URL — auto-injected on Render, e.g. https://foo.onrender.com.
	//   3. Fallback to localhost for local dev.
	const baseUrlRaw =
		process.env.MCP_BASE_URL ?? process.env.RENDER_EXTERNAL_URL ?? `http://localhost:${port}`;
	const publicBaseUrl = new URL(baseUrlRaw);

	const clientId = requireEnv('OAUTH_CLIENT_ID');
	const clientSecret = requireEnv('OAUTH_CLIENT_SECRET');
	const redirectUris = (
		process.env.OAUTH_REDIRECT_URIS ??
		'https://claude.ai/api/mcp/auth_callback,http://localhost:33418/oauth/callback'
	)
		.split(',')
		.map((u) => u.trim())
		.filter(Boolean);

	// Default DCR ON: Claude.ai's connector flow uses Dynamic Client Registration
	// (the Advanced-Settings UI for static creds isn't exposed in the web flow).
	// Set OAUTH_ALLOW_DYNAMIC_REGISTRATION=false to lock down to the pre-registered
	// client only — Claude Desktop with Advanced Settings still works in that mode.
	const allowDynamicRegistration = process.env.OAUTH_ALLOW_DYNAMIC_REGISTRATION !== 'false';

	return {
		port,
		host,
		publicBaseUrl,
		mcpPath: process.env.MCP_PATH ?? '/mcp',
		client: { clientId, clientSecret, redirectUris },
		allowDynamicRegistration,
	};
}

export function buildHttpApp(config: HttpServerConfig): express.Express {
	const provider = new InMemoryOAuthProvider({
		client: config.client,
		allowDynamicRegistration: config.allowDynamicRegistration,
	});

	const app = express();
	app.disable('x-powered-by');
	// On Render (and most PaaS), inbound requests reach Express via a single
	// reverse proxy that sets X-Forwarded-For/Proto. Without this, the SDK's
	// internal express-rate-limit middleware throws ERR_ERL_UNEXPECTED_X_FORWARDED_FOR
	// on /authorize and /token, breaking the OAuth handshake.
	app.set('trust proxy', 1);

	// Lightweight access log for the OAuth/MCP routes. Helps diagnose connector
	// failures from MCP clients (Claude.ai, Claude Desktop) since Render free
	// tier doesn't expose request logs separately.
	if (process.env.LOG_REQUESTS !== 'false') {
		app.use((req, res, next) => {
			const start = Date.now();
			const ua = req.headers['user-agent'] ?? '';
			res.on('finish', () => {
				const ms = Date.now() - start;
				console.log(
					`[req] ${req.method} ${req.originalUrl} -> ${res.statusCode} ${ms}ms ua="${String(ua).slice(0, 80)}"`,
				);
			});
			next();
		});
	}

	// OAuth diagnostic logger: logs sanitized payloads for /register, /authorize,
	// /token so we can see what an MCP client actually sent when an error like
	// "Invalid client_secret" comes back. Disable with LOG_OAUTH=false.
	if (process.env.LOG_OAUTH !== 'false') {
		const oauthDiag = express.urlencoded({ extended: false });
		const oauthDiagJson = express.json();
		const tag = (s: string | undefined, n = 8) =>
			s ? `${s.slice(0, n)}…(len=${s.length})` : '<absent>';
		app.use(['/token', '/authorize', '/register'], (req, _res, next) => {
			const ct = req.headers['content-type'] ?? '';
			const handler = ct.includes('json') ? oauthDiagJson : oauthDiag;
			handler(req, _res, (err) => {
				if (err) return next(err);
				const body = (req.body ?? {}) as Record<string, unknown>;
				const q = req.query as Record<string, unknown>;
				const merged = { ...q, ...body };
				const summary: Record<string, unknown> = {
					path: req.path,
					method: req.method,
					grant_type: merged.grant_type,
					client_id: tag(merged.client_id as string | undefined, 16),
					client_secret: tag(merged.client_secret as string | undefined, 6),
					redirect_uri: merged.redirect_uri,
					code_challenge_method: merged.code_challenge_method,
					token_endpoint_auth_method: merged.token_endpoint_auth_method,
				};
				console.log(`[oauth] ${JSON.stringify(summary)}`);
				next();
			});
		});
	}

	// Liveness probe (Render's health check hits this if configured).
	app.get('/healthz', (_req, res) => {
		res.json({ status: 'ok' });
	});

	// RFC 9728 / MCP discovery: when the protected resource has a non-root path
	// (we use /mcp), modern clients also probe path-suffixed well-known URLs:
	//   /.well-known/oauth-protected-resource/mcp
	//   /.well-known/oauth-authorization-server/mcp
	// The SDK's router only mounts the un-suffixed variants; mirror them here so
	// Claude.ai's connector discovery (which uses the suffixed form) succeeds.
	// These must be registered BEFORE mcpAuthRouter — the SDK mounts the
	// un-suffixed routes via `router.use(...)` which prefix-matches and the
	// inner router ends the response with 404 rather than falling through.
	const oauthMetadata = createOAuthMetadata({
		provider,
		issuerUrl: config.publicBaseUrl,
		scopesSupported: [],
	});
	const protectedResourceMetadata = {
		resource: config.publicBaseUrl.href,
		authorization_servers: [oauthMetadata.issuer],
		scopes_supported: [],
		resource_name: 'MCP Wayback Machine',
	};
	app.use(
		`/.well-known/oauth-protected-resource${config.mcpPath}`,
		metadataHandler(protectedResourceMetadata),
	);
	app.use(
		`/.well-known/oauth-authorization-server${config.mcpPath}`,
		metadataHandler(oauthMetadata),
	);

	// OAuth metadata + /authorize + /token + /register endpoints. Mounted at root
	// because the un-suffixed well-known metadata paths resolve at the issuer origin.
	app.use(
		mcpAuthRouter({
			provider,
			issuerUrl: config.publicBaseUrl,
			scopesSupported: [],
			resourceName: 'MCP Wayback Machine',
		}),
	);

	const resourceMetadataUrl = new URL(
		`/.well-known/oauth-protected-resource${config.mcpPath}`,
		config.publicBaseUrl,
	).href;

	const requireAuth = requireBearerAuth({
		verifier: provider,
		resourceMetadataUrl,
	});

	app.all(config.mcpPath, requireAuth, express.json(), async (req: Request, res: Response) => {
		// Stateless transport: each request is independent. This is required for
		// Render's free tier, where in-memory session state is lost on cold start.
		const transport = new StreamableHTTPServerTransport({
			sessionIdGenerator: undefined,
			enableJsonResponse: true,
		});
		const server = createMcpServer();

		res.on('close', () => {
			transport.close().catch(() => undefined);
			server.close().catch(() => undefined);
		});

		try {
			await server.connect(transport);
			await transport.handleRequest(req, res, req.body);
		} catch (error) {
			console.error('MCP request failed:', error);
			if (!res.headersSent) {
				res.status(500).json({
					jsonrpc: '2.0',
					error: { code: -32603, message: 'Internal server error' },
					id: null,
				});
			}
		}
	});

	return app;
}

export async function startHttpServer(): Promise<void> {
	const config = loadHttpConfigFromEnv();
	const app = buildHttpApp(config);

	app.listen(config.port, config.host, () => {
		console.error(
			`MCP Wayback Machine HTTP server listening on http://${config.host}:${config.port} ` +
				`(public: ${config.publicBaseUrl.href}, mcp: ${config.mcpPath})`,
		);
	});
}

function requireEnv(name: string): string {
	const value = process.env[name];
	if (!value) {
		throw new Error(`Missing required environment variable: ${name}`);
	}
	return value;
}
