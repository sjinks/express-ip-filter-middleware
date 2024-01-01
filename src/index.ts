import { BlockList, isIP } from 'node:net';
import type { NextFunction, Request, Response, RequestHandler } from 'express';

export type BlockMode = 'allow' | 'deny';
export interface Options {
    mode: BlockMode;
    allow?: BlockList | undefined;
    deny?: BlockList | undefined;
    ipOverride?: ((req: Request) => string) | undefined;
}

export class IPRelatedError extends Error {
    public readonly ip: string;

    constructor(message: string, ip: string) {
        super(message);
        this.ip = ip;
    }
}

export class IPBlockedError extends IPRelatedError {
    constructor(message: string, ip: string) {
        super(message, ip);
        this.name = 'IPBlockedError';
    }
}

export class InvalidIPError extends IPRelatedError {
    constructor(message: string, ip: string) {
        super(message, ip);
        this.name = 'InvalidIPError';
    }
}

export class IPUnavailableError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'IPUnavailableError';
    }
}

export function ipFilterMiddleware(options: Options): RequestHandler {
    const { allow = new BlockList(), deny = new BlockList(), ipOverride = (req: Request) => req.ip } = options;

    return function (req: Request, _res: Response, next: NextFunction): void {
        const ip = ipOverride(req);

        // `ip` may be undefined if the `req.socket` is destroyed (for example, if the client disconnected).
        if (ip === undefined) {
            next(new IPUnavailableError('IP address is unavailable'));
            return;
        }

        const type = isIP(ip);
        if (!type) {
            next(new InvalidIPError(`IP Address ${ip} is not valid`, ip));
            return;
        }

        const addrType = type === 4 ? 'ipv4' : 'ipv6';
        const allowed = allow.check(ip, addrType);
        const denied = deny.check(ip, addrType);

        /*
            ALLOW if:
                - `mode` is 'allow' AND `ip` is allowed AND `ip` is NOT denied
                - `mode` is 'deny' AND `ip` is allowed
                - `mode` is 'deny' AND `ip` is NOT denied

            Given that ALLOW is a binary value (either allow or deny), we can simplify the above to:
                - `ip` is allowed AND `ip` is NOT denied
                - `mode` is 'deny' AND `ip` is allowed
                - `mode` is 'deny' AND `ip` is NOT denied
        */
        const denyMode = options.mode === 'deny';
        const error =
            (allowed && !denied) || (denyMode && (allowed || !denied))
                ? undefined
                : new IPBlockedError('Access denied', ip);
        next(error);
    };
}
