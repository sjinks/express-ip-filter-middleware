# express-ip-filter-middleware

[![Build & Test](https://github.com/sjinks/express-ip-filter-middleware/actions/workflows/build-test.yml/badge.svg)](https://github.com/sjinks/express-ip-filter-middleware/actions/workflows/build-test.yml)
[![CodeQL](https://github.com/sjinks/express-ip-filter-middleware/actions/workflows/codeql.yml/badge.svg)](https://github.com/sjinks/express-ip-filter-middleware/actions/workflows/codeql.yml)

Express middleware for access control using IP / CIDR lists.

## Installation

```bash
npm install express-ip-filter-middleware 
```

## Usage

```typescript
import { BlockList } from 'node:net';
import express from 'express';
import { ipFilterMiddleware } from 'express-ip-filter-middleware';

const allow = new BlockList();
allow.addSubnet('192.168.0.0', 16);

const deny = new BlockList();
deny.addAddress('192.168.0.1');

const options = {
    mode: 'whitelist',
    allow,
    deny,
};

const app = express();
app.use(ipFilterMiddleware(options))
```

`express-ip-filter-middleware` generates a middleware that allows or blocks access per the specified options.

Options is an object with the following fields:
  * `mode: 'whitelist' | 'blacklist'` (**required**): operation mode. In `blacklist` mode, everything is allowed except for the explicitly blacklisted items (specified in `deny`), unless overridden by `allow`. In `whitelist` mode, everything is forbidden except for explicitly allowed items (specified in `allow`), unless overridden by `deny`;
  * `allow: net.BlockList`: optional list of the allowed addresses;
  * `deny: net.BlockList`: optional list of the denied addresses;
  * `ipOverride: (req: express.Request) => string | undefined`: optional function to retrieve the IP address to check. If this function is not specified, `req.ip` is used. If this function returns an invalid IP address, the middleware bails out with an error.

The mode of operation is similar to Apache's `mod_access` `Order` directive: `whitelist` works like `Order Allow,Deny`: to allow access, the IP address must match the `allow` list, and must not be listed in the `deny` list. Consequently, empty `allow` and `deny` in `allow` mode will result in denied access.

`blacklist` mode works like `Order Deny,Allow`: the request is allowed if the IP address is listed in the `allow` list *or* not listed in the `deny` list.
