# express-ip-filter-middleware

![Build and Test CI](https://github.com/sjinks/express-ip-filter-middleware/workflows/Build%20and%20Test%20CI/badge.svg)

Express middleware for access control using IP / CIDR lists

## Installation

```bash
npm install express-ip-filter-middleware 
```

## Usage

```typescript
import express from 'express';
import middleware from 'express-ip-filter-middleware';

const options = {
    mode: 'whitelist',
    allow: ['192.168.0.0/16'],
    deny: ['192.168.0.1'],
};

const app = express();
app.use(middleware(options))
```

`express-ip-filter-middleware` generates a middleware which allows or blocks access in accordance with the specified options.

Options is an object with the following fields:
  * `mode: 'blacklist' | 'whitelist'` (**required**): operation mode. In `blacklist` mode, everything is allowed except for blacklisted items (specified in `deny`), unless overridden by `allow`. In `whitelist` mode, everything is forbidden except for explicitly allowed items (specified in `allow`), unless overridden by `deny`;
  * `allow: string[]`: optional list of the allowed IPv4 or IPv6 addresses or CIDRs (defaults to `[]`);
  * `deny: string[]`: optional list of the denied IPv4 or IPv6 addresses or CIDRs (defaults to `[]`);
  * `ipOverride: (req: express.Request) => string`: optional function to retrieve the IP address to check. If this function is not specified or set to `null`, `req.ip` is used. If this function returns an invalid IP address, the middleware bails out with an error.

The mode of operation is similar to Apache's `mod_access` `Order` directive: `whitelist` works like `Order Allow,Deny`: to allow access, the IP address must match the `allow` list, and must not be listed in the `deny` list. As a consequence, empty `allow` and `deny` in `whitelist` mode will result in denied access.

`blacklist` mode works like `Order deny,allow`: the request is allowed if the IP address is listed in the `allow` list *or* not listed in the `deny` list.
