import { BlockList } from 'node:net';
import request from 'supertest';
import express, { type Application, type NextFunction, type Request, type Response } from 'express';
import { IPBlockedError, Options, ipFilterMiddleware } from '..';

function buildServer(options: Options): Application {
    const server = express();
    server.enable('trust proxy');
    server.use(ipFilterMiddleware(options));
    server.use((_req: Request, res: Response): unknown => res.json({ status: 200 }));
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    server.use((err: Error, _req: Request, res: Response, _next: NextFunction): unknown =>
        res.status(err instanceof IPBlockedError ? 403 : 500).json(err),
    );
    return server;
}

describe('express-ip-filter-middleware', function (): void {
    it('should deny everyone in WHITELIST mode with empty lists', function () {
        const server = buildServer({ mode: 'whitelist' });
        return request(server).get('/').set('X-Forwarded-For', '192.168.2.1').expect(403);
    });

    it('should allow everyone in BLACKLIST mode with empty lists', function () {
        const server = buildServer({ mode: 'blacklist' });
        return request(server).get('/').set('X-Forwarded-For', '192.168.2.1').expect(200);
    });

    it('should favor allow in BLACKLIST mode', function () {
        const list = new BlockList();
        list.addAddress('192.168.2.1');
        const server = buildServer({ mode: 'blacklist', allow: list, deny: list });
        return request(server).get('/').set('X-Forwarded-For', '192.168.2.1').expect(200);
    });

    it('should favor deny in WHITELIST mode', function () {
        const list = new BlockList();
        list.addAddress('192.168.2.1');

        const server = buildServer({ mode: 'whitelist', allow: list, deny: list });
        return request(server).get('/').set('X-Forwarded-For', '192.168.2.1').expect(403);
    });

    it('should take the IP address from ipOverride()', function () {
        const allow = new BlockList();
        allow.addAddress('192.168.2.5');

        const server = buildServer({
            mode: 'whitelist',
            allow,
            ipOverride: () => '::ffff:192.168.2.5',
        });

        return request(server).get('/').set('X-Forwarded-For', '192.168.2.1').expect(200);
    });

    it('should fail if ipOverride() returns a bad IP', function () {
        const server = buildServer({
            mode: 'whitelist',
            ipOverride: () => '192.168.2.500',
        });

        return request(server).get('/').set('X-Forwarded-For', '192.168.2.1').expect(500);
    });

    it('should fail if IP address cannot be determined', function () {
        const server = buildServer({
            mode: 'whitelist',
            ipOverride: () => undefined,
        });

        return request(server).get('/').expect(500);
    });
});
