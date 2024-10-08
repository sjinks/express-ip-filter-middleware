/* eslint-disable sonarjs/no-redundant-optional */
import { BlockList, isIP } from 'node:net';
import type { NextFunction, Request, RequestHandler, Response } from 'express';

export type BlockMode = 'whitelist' | 'blacklist';
export type IPOverrideFunction = (req: Request) => string | undefined;

export interface Options {
    mode: BlockMode;
    allow?: BlockList | undefined;
    deny?: BlockList | undefined;
    ipOverride?: IPOverrideFunction | undefined;
}

export class IPRelatedError extends Error {
    public readonly ip: string;

    public constructor(message: string, ip: string) {
        super(message);
        this.ip = ip;
    }
}

export class IPBlockedError extends IPRelatedError {
    public constructor(message: string, ip: string) {
        super(message, ip);
        this.name = 'IPBlockedError';
    }
}

export class InvalidIPError extends IPRelatedError {
    public constructor(message: string, ip: string) {
        super(message, ip);
        this.name = 'InvalidIPError';
    }
}

export class IPUnavailableError extends Error {
    public constructor(message: string) {
        super(message);
        this.name = 'IPUnavailableError';
    }
}

const getIP: IPOverrideFunction = (req) => req.ip;

export function ipFilterMiddleware(options: Options): RequestHandler {
    const { allow = new BlockList(), deny = new BlockList(), ipOverride = getIP } = options;

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
                - `mode` is 'whitelist' AND `ip` is allowed AND `ip` is NOT denied
                - `mode` is 'blacklist' AND `ip` is allowed
                - `mode` is 'blacklist' AND `ip` is NOT denied

            Given that ALLOW is a binary value (either `whitelist` or `blacklist`), we can simplify the above to:
                - `ip` is allowed AND `ip` is NOT denied
                - `mode` is 'blacklist' AND (`ip` is allowed OR `ip` is NOT denied)
        */
        const black = options.mode === 'blacklist';
        const error =
            (allowed && !denied) || (black && (allowed || !denied))
                ? undefined
                : new IPBlockedError('Access denied', ip);
        next(error);
    };
}
