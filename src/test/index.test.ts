import { BlockList } from 'node:net';
import request from 'supertest';
import express, { type Application, type Request, type Response, type NextFunction } from 'express';
import { Options, IPBlockedError, ipFilterMiddleware } from '..';

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

describe('express-ip-filter-middleware', (): void => {
    it('should deny everyone in ALLOW mode with empty lists', async (): Promise<unknown> => {
        const server = buildServer({ mode: 'allow' });
        return request(server).get('/').set('X-Forwarded-For', '192.168.2.1').expect(403);
    });

    it('should allow everyone in DENY mode with empty lists', async (): Promise<unknown> => {
        const server = buildServer({ mode: 'deny' });
        return request(server).get('/').set('X-Forwarded-For', '192.168.2.1').expect(200);
    });

    it('should parse CIDRs', async (): Promise<unknown> => {
        const allow = new BlockList();
        allow.addSubnet('192.168.2.0', 24);
        const server = buildServer({ mode: 'allow', allow });
        return request(server).get('/').set('X-Forwarded-For', '192.168.2.1').expect(200);
    });

    it('should favor allow in DENY mode (single IP)', async (): Promise<unknown> => {
        const list = new BlockList();
        list.addAddress('192.168.2.1');
        const server = buildServer({ mode: 'deny', allow: list, deny: list });
        return request(server).get('/').set('X-Forwarded-For', '192.168.2.1').expect(200);
    });

    it('should favor allow in BLACKLIST mode (IP range)', async (): Promise<unknown> => {
        const allow = new BlockList();
        allow.addAddress('192.168.2.1');

        const deny = new BlockList();
        deny.addSubnet('192.168.2.0', 24);

        const server = buildServer({ mode: 'deny', allow, deny });
        return request(server).get('/').set('X-Forwarded-For', '192.168.2.1').expect(200);
    });

    it('should favor deny in ALLOW mode (single IP)', async (): Promise<unknown> => {
        const list = new BlockList();
        list.addAddress('192.168.2.1');

        const server = buildServer({ mode: 'allow', allow: list, deny: list });
        return request(server).get('/').set('X-Forwarded-For', '192.168.2.1').expect(403);
    });

    it('should favor deny in ALLOW mode (IP range)', async (): Promise<unknown> => {
        const allow = new BlockList();
        allow.addAddress('192.168.2.1');

        const deny = new BlockList();
        deny.addSubnet('192.168.2.0', 24);

        const server = buildServer({ mode: 'allow', allow, deny });
        return request(server).get('/').set('X-Forwarded-For', '192.168.2.1').expect(403);
    });

    it('should take the IP address from ipOverride()', async (): Promise<unknown> => {
        const allow = new BlockList();
        allow.addAddress('192.168.2.5');

        const server = buildServer({
            mode: 'allow',
            allow,
            ipOverride: (): string => '192.168.2.5',
        });

        return request(server).get('/').set('X-Forwarded-For', '192.168.2.1').expect(200);
    });

    it('should fail if ipOverride() returns a bad IP', async (): Promise<unknown> => {
        const allow = new BlockList();
        allow.addAddress('192.168.2.5');

        const server = buildServer({
            mode: 'allow',
            allow,
            ipOverride: (): string => '192.168.2.500',
        });

        return request(server).get('/').set('X-Forwarded-For', '192.168.2.1').expect(500);
    });

    it('should be able to parse IPv6 address', async (): Promise<unknown> => {
        const deny = new BlockList();
        deny.addAddress('2001:DB8:85A3::8A2E:370:7334', 'ipv6');
        const server = buildServer({ mode: 'deny', deny });
        return request(server).get('/').set('X-Forwarded-For', '2001:0db8:85a3:0000:0000:8a2e:0370:7334').expect(403);
    });

    it('should be able to parse IPv6 CIDR', async (): Promise<unknown> => {
        const allow = new BlockList();
        allow.addSubnet('2001:DB8:85A3::', 48, 'ipv6');
        const server = buildServer({ mode: 'allow', allow });
        return request(server).get('/').set('X-Forwarded-For', '2001:0db8:85a3:0000:0000:8a2e:0370:7334').expect(200);
    });
});
