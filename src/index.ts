import { NextFunction, Request, Response, RequestHandler } from 'express';
import ipaddr, { IPv4, IPv6, parseCIDR, process as processIP, isValid } from 'ipaddr.js';

export interface Options {
    mode: 'whitelist' | 'blacklist';
    allow?: string[];
    deny?: string[];
    ipOverride?: ((req: Request) => string) | null;
}

type IPRange = [IPv4 | IPv6, number];

function parse(item: string): IPRange | null {
    try {
        if (item.indexOf('/') !== -1) {
            return parseCIDR(item);
        }

        const addr = processIP(item);
        return [addr, addr.kind() === 'ipv4' ? 32 : 128];
    } catch (e) {
        return null;
    }
}

function matchIP(ip: IPv4 | IPv6, list: IPRange[]): boolean {
    return list.some(
        (item: IPRange): boolean =>
            ip.kind() === item[0].kind() && (ip as ipaddr.IPv4).match(item as [ipaddr.IPv4, number]),
    );
}

export class IPBlockedError extends Error {
    public readonly ip: string;

    constructor(message: string, ip: string) {
        super(message);
        this.ip = ip;
    }
}

export default function (options: Options): RequestHandler {
    const allow = (options.allow || []).map(parse).filter(Boolean) as IPRange[];
    const deny = (options.deny || []).map(parse).filter(Boolean) as IPRange[];

    return function (req: Request, res: Response, next: NextFunction): void {
        const ip = options.ipOverride ? options.ipOverride(req) : req.ip;
        if (!isValid(ip)) {
            next(new Error(`IP Address ${ip} is not valid`));
            return;
        }

        const addr = processIP(ip);
        const allowed = matchIP(addr, allow);
        const denied = matchIP(addr, deny);

        /*
            ALLOW if:
                - mode is whitelist AND ip is allowed AND ip is NOT denied
                - mode is blacklist AND ip is allowed
                - mode is blacklist AND ip is NOT denied
        */
        if ((allowed && !denied) || (options.mode === 'blacklist' && (allowed || !denied))) {
            next();
        }

        next(new IPBlockedError('Access denied', ip));
    };
}
