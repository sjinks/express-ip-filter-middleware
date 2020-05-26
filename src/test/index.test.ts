import request from 'supertest';
import express, { Request, Response, NextFunction } from 'express';
import middleware, { Options, IPBlockedError } from '..';

function buildServer(options: Options): express.Application {
    const server = express();
    server.enable('trust proxy');
    server.use(middleware(options));
    server.use((req: Request, res: Response): unknown => res.json({ status: 200 }));
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    server.use((err: Error, req: Request, res: Response, next: NextFunction): unknown =>
        res.status(err instanceof IPBlockedError ? 403 : 500).json(err),
    );
    return server;
}

describe('express-ip-filter-middleware', (): void => {
    it('should deny everyone in WHITELIST mode with empty lists', async (): Promise<unknown> => {
        const server = buildServer({ mode: 'whitelist' });
        return request(server)
            .get('/')
            .set('X-Forwarded-For', '192.168.2.1')
            .expect(403);
    });

    it('should allow everyone in BLACKLIST mode with empty lists', async (): Promise<unknown> => {
        const server = buildServer({ mode: 'blacklist' });
        return request(server)
            .get('/')
            .set('X-Forwarded-For', '192.168.2.1')
            .expect(200);
    });

    it('should parse CIDRs', async (): Promise<unknown> => {
        const server = buildServer({ mode: 'whitelist', allow: ['192.168.2.0/24'] });
        return request(server)
            .get('/')
            .set('X-Forwarded-For', '192.168.2.1')
            .expect(200);
    });

    it('should ignore invalid IPs in lists', async (): Promise<unknown> => {
        const server = buildServer({ mode: 'whitelist', allow: ['192.168.2.256'] });
        return request(server)
            .get('/')
            .set('X-Forwarded-For', '192.168.2.1')
            .expect(403);
    });

    it('should favor allow in BLACKLIST mode (single IP)', async (): Promise<unknown> => {
        const server = buildServer({ mode: 'blacklist', allow: ['192.168.2.1'], deny: ['192.168.2.1'] });
        return request(server)
            .get('/')
            .set('X-Forwarded-For', '192.168.2.1')
            .expect(200);
    });

    it('should favor allow in BLACKLIST mode (IP range)', async (): Promise<unknown> => {
        const server = buildServer({ mode: 'blacklist', allow: ['192.168.2.1'], deny: ['192.168.2.0/24'] });
        return request(server)
            .get('/')
            .set('X-Forwarded-For', '192.168.2.1')
            .expect(200);
    });

    it('should favor deny in WHITELIST mode (single IP)', async (): Promise<unknown> => {
        const server = buildServer({ mode: 'whitelist', allow: ['192.168.2.1'], deny: ['192.168.2.1'] });
        return request(server)
            .get('/')
            .set('X-Forwarded-For', '192.168.2.1')
            .expect(403);
    });

    it('should favor deny in WHITELIST mode (IP range)', async (): Promise<unknown> => {
        const server = buildServer({ mode: 'whitelist', allow: ['192.168.2.1'], deny: ['192.168.2.0/24'] });
        return request(server)
            .get('/')
            .set('X-Forwarded-For', '192.168.2.1')
            .expect(403);
    });

    it('should take the IP address from ipOverride()', async (): Promise<unknown> => {
        const server = buildServer({
            mode: 'whitelist',
            allow: ['192.168.2.5'],
            ipOverride: (): string => '192.168.2.5',
        });

        return request(server)
            .get('/')
            .set('X-Forwarded-For', '192.168.2.1')
            .expect(200);
    });

    it('should fail if ipOverride() returns a bad IP', async (): Promise<unknown> => {
        const server = buildServer({
            mode: 'whitelist',
            allow: ['192.168.2.5'],
            ipOverride: (): string => '192.168.2.500',
        });

        return request(server)
            .get('/')
            .set('X-Forwarded-For', '192.168.2.1')
            .expect(500);
    });

    it('should be able to parse IPv6 address', async (): Promise<unknown> => {
        const server = buildServer({ mode: 'blacklist', deny: ['2001:DB8:85A3::8A2E:370:7334'] });
        return request(server)
            .get('/')
            .set('X-Forwarded-For', '2001:0db8:85a3:0000:0000:8a2e:0370:7334')
            .expect(403);
    });

    it('should be able to parse IPv6 CIDR', async (): Promise<unknown> => {
        const server = buildServer({ mode: 'whitelist', allow: ['2001:0db8:85a3::/48'] });
        return request(server)
            .get('/')
            .set('X-Forwarded-For', '2001:0db8:85a3:0000:0000:8a2e:0370:7334')
            .expect(200);
    });
});
