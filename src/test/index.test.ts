/* eslint-disable sonarjs/no-hardcoded-ip */
/* eslint-disable sonarjs/assertions-in-tests */
import { BlockList } from 'node:net';
import { describe, it } from 'node:test';
import request from 'supertest';
import express, { type Application, type NextFunction, type Request, type Response } from 'express';
import { IPBlockedError, Options, ipFilterMiddleware } from '..';

function buildServer(options: Options): Application {
    const server = express();
    server.enable('trust proxy');
    server.use(ipFilterMiddleware(options));
    server.use((_req: Request, res: Response): unknown => res.json({ status: 200 }));
    server.use((err: Error, _req: Request, res: Response, _next: NextFunction): unknown =>
        res.status(err instanceof IPBlockedError ? 403 : 500).json(err),
    );
    return server;
}

const promiseVoid = (): Promise<void> => Promise.resolve();

void describe('express-ip-filter-middleware', async () => {
    await it('should deny everyone in WHITELIST mode with empty lists', () => {
        const server = buildServer({ mode: 'whitelist' });
        return request(server).get('/').set('X-Forwarded-For', '192.168.2.1').expect(403).then(promiseVoid);
    });

    await it('should allow everyone in BLACKLIST mode with empty lists', () => {
        const server = buildServer({ mode: 'blacklist' });
        return request(server).get('/').set('X-Forwarded-For', '192.168.2.1').expect(200).then(promiseVoid);
    });

    await it('should favor allow in BLACKLIST mode', () => {
        const list = new BlockList();
        list.addAddress('192.168.2.1');
        const server = buildServer({ mode: 'blacklist', allow: list, deny: list });
        return request(server).get('/').set('X-Forwarded-For', '192.168.2.1').expect(200).then(promiseVoid);
    });

    await it('should favor deny in WHITELIST mode', () => {
        const list = new BlockList();
        list.addAddress('192.168.2.1');

        const server = buildServer({ mode: 'whitelist', allow: list, deny: list });
        return request(server).get('/').set('X-Forwarded-For', '192.168.2.1').expect(403).then(promiseVoid);
    });

    await it('should take the IP address from ipOverride()', () => {
        const allow = new BlockList();
        allow.addAddress('192.168.2.5');

        const server = buildServer({
            mode: 'whitelist',
            allow,
            ipOverride: () => '::ffff:192.168.2.5',
        });

        return request(server).get('/').set('X-Forwarded-For', '192.168.2.1').expect(200).then(promiseVoid);
    });

    await it('should fail if ipOverride() returns a bad IP', () => {
        const server = buildServer({
            mode: 'whitelist',
            ipOverride: () => '192.168.2.500',
        });

        return request(server).get('/').set('X-Forwarded-For', '192.168.2.1').expect(500).then(promiseVoid);
    });

    await it('should fail if IP address cannot be determined', () => {
        const server = buildServer({
            mode: 'whitelist',
            ipOverride: () => undefined,
        });

        return request(server).get('/').expect(500).then(promiseVoid);
    });
});
