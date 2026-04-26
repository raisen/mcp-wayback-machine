#!/usr/bin/env node
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

import { createMcpServer } from './server.js';

async function main(): Promise<void> {
	const transportMode = (process.env.MCP_TRANSPORT ?? '').toLowerCase();
	const isHttpMode = transportMode === 'http' || (transportMode === '' && !!process.env.PORT);

	if (isHttpMode) {
		const { startHttpServer } = await import('./http.js');
		await startHttpServer();
		return;
	}

	const isCliMode = process.stdin.isTTY || process.argv.length > 2;
	if (isCliMode && process.argv.length > 2) {
		const { createCLI } = await import('./cli.js');
		const program = createCLI();
		await program.parseAsync(process.argv);
		return;
	}

	const server = createMcpServer();
	const transport = new StdioServerTransport();
	await server.connect(transport);
	console.error('MCP Wayback Machine server running on stdio');
}

main().catch((error) => {
	console.error('Fatal error:', error);
	process.exit(1);
});
