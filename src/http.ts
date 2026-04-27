import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import { mcpAuthRouter } from '@modelcontextprotocol/sdk/server/auth/router.js';
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

	return {
		port,
		host,
		publicBaseUrl,
		mcpPath: process.env.MCP_PATH ?? '/mcp',
		client: { clientId, clientSecret, redirectUris },
	};
}

export function buildHttpApp(config: HttpServerConfig): express.Express {
	const provider = new InMemoryOAuthProvider({ client: config.client });

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

	// Liveness probe (Render's health check hits this if configured).
	app.get('/healthz', (_req, res) => {
		res.json({ status: 'ok' });
	});

	// OAuth metadata + /authorize + /token endpoints. Mounted at root because the
	// well-known metadata paths must resolve at the issuer origin.
	app.use(
		mcpAuthRouter({
			provider,
			issuerUrl: config.publicBaseUrl,
			scopesSupported: [],
			resourceName: 'MCP Wayback Machine',
		}),
	);

	const resourceMetadataUrl = new URL(
		'/.well-known/oauth-protected-resource',
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
