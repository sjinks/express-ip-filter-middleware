/* eslint-disable sonarjs/no-hardcoded-ip */
/* eslint-disable sonarjs/assertions-in-tests */
import { BlockList } from 'node:net';
import { describe, it } from 'node:test';
import request from 'supertest';
import express, { type Application, type NextFunction, type Request, type Response } from 'express';
import { IPBlockedError, Options, ipFilterMiddleware } from '../src';

function buildServer(options: Options): Application {
    const server = express();
    server.enable('trust proxy');
    server.use(ipFilterMiddleware(options));
    server.use((_req: Request, res: Response): void => {
        res.json({ status: 200 });
    });
    server.use((err: Error, _req: Request, res: Response, _next: NextFunction): void => {
        res.status(err instanceof IPBlockedError ? 403 : 500).json(err);
    });
    return server;
}

void describe('express-ip-filter-middleware', async () => {
    await it('should deny everyone in WHITELIST mode with empty lists', async () => {
        const server = buildServer({ mode: 'whitelist' });
        await request(server).get('/').set('X-Forwarded-For', '192.168.2.1').expect(403);
    });

    await it('should allow everyone in BLACKLIST mode with empty lists', async () => {
        const server = buildServer({ mode: 'blacklist' });
        await request(server).get('/').set('X-Forwarded-For', '192.168.2.1').expect(200);
    });

    await it('should favor allow in BLACKLIST mode', async () => {
        const list = new BlockList();
        list.addAddress('192.168.2.1');
        const server = buildServer({ mode: 'blacklist', allow: list, deny: list });
        await request(server).get('/').set('X-Forwarded-For', '192.168.2.1').expect(200);
    });

    await it('should favor deny in WHITELIST mode', async () => {
        const list = new BlockList();
        list.addAddress('192.168.2.1');

        const server = buildServer({ mode: 'whitelist', allow: list, deny: list });
        await request(server).get('/').set('X-Forwarded-For', '192.168.2.1').expect(403);
    });

    await it('should take the IP address from ipOverride()', async () => {
        const allow = new BlockList();
        allow.addAddress('192.168.2.5');

        const server = buildServer({
            mode: 'whitelist',
            allow,
            ipOverride: () => '::ffff:192.168.2.5',
        });

        await request(server).get('/').set('X-Forwarded-For', '192.168.2.1').expect(200);
    });

    await it('should fail if ipOverride() returns a bad IP', async () => {
        const server = buildServer({
            mode: 'whitelist',
            ipOverride: () => '192.168.2.500',
        });

        await request(server).get('/').set('X-Forwarded-For', '192.168.2.1').expect(500);
    });

    await it('should fail if IP address cannot be determined', async () => {
        const server = buildServer({
            mode: 'whitelist',
            ipOverride: () => undefined,
        });

        await request(server).get('/').expect(500);
    });
});
