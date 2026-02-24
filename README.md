# Archon OAuth Server

A standalone OAuth 2.0 Authorization Server using Archon DID authentication.

## Key Features

- **OAuth 2.0 Authorization Code Flow** — Standard OAuth implementation
- **Archon Challenge/Response** — Replaces username/password with DID-based authentication
- **Response DID as Access Token** — Self-validating tokens via Archon resolution
- **OIDC Discovery** — Compatible with standard OAuth/OIDC clients

## How It Works

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────┐
│ Client App  │     │  OAuth Server    │     │   User Wallet   │
└──────┬──────┘     └────────┬─────────┘     └────────┬────────┘
       │                     │                        │
       │ 1. Redirect to      │                        │
       │    /oauth/authorize │                        │
       │────────────────────>│                        │
       │                     │                        │
       │                     │ 2. Create Challenge    │
       │                     │    (show QR code)      │
       │                     │                        │
       │                     │ 3. User scans/clicks   │
       │                     │<───────────────────────│
       │                     │                        │
       │                     │ 4. Wallet sends        │
       │                     │    Response DID        │
       │                     │<───────────────────────│
       │                     │                        │
       │ 5. Redirect with    │                        │
       │    auth code        │                        │
       │<────────────────────│                        │
       │                     │                        │
       │ 6. Exchange code    │                        │
       │    for token        │                        │
       │────────────────────>│                        │
       │                     │                        │
       │ 7. Access token     │                        │
       │    (Response DID!)  │                        │
       │<────────────────────│                        │
```

## Quick Start

### 1. Install dependencies

```bash
npm install
```

### 2. Configure environment

```bash
cp sample.env .env
# Edit .env with your settings
```

### 3. Build and run

```bash
npm run build
npm start
```

Or for development:

```bash
npm run dev
```

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | `3000` |
| `HOST_URL` | Public URL of this server | `http://localhost:3000` |
| `GATEKEEPER_URL` | Archon Gatekeeper URL | `http://localhost:4224` |
| `WALLET_URL` | Archon Wallet URL | `https://wallet.archon.technology` |
| `WALLET_PASSPHRASE` | Passphrase for server wallet | *required* |
| `SESSION_SECRET` | Express session secret | *change in production* |
| `CORS_ORIGIN` | Allowed CORS origins | `*` |

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /oauth/authorize` | Authorization endpoint (shows QR code) |
| `POST /oauth/callback` | Receives response from wallet |
| `POST /oauth/token` | Exchanges auth code for access token |
| `GET /oauth/userinfo` | Returns user info (requires Bearer token) |
| `GET /oauth/.well-known/openid-configuration` | OIDC discovery document |
| `POST /api/clients` | Register a new OAuth client |

## Client Registration

Register an OAuth client:

```bash
curl -X POST http://localhost:3000/api/clients \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "my-app",
    "client_secret": "my-secret",
    "name": "My Application",
    "redirect_uris": ["http://localhost:4000/callback"]
  }'
```

A demo client is pre-registered:
- **client_id:** `demo-client`
- **client_secret:** `demo-secret`
- **redirect_uris:** `localhost:3001/callback`, `localhost:4000/callback`

## Token Response

The `/oauth/token` endpoint returns:

```json
{
  "access_token": "did:cid:bagaaiera...",  // Response DID!
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid profile",
  "responder_did": "did:cid:bagaaiera...",  // User's DID
  "response_did": "did:cid:bagaaiera..."    // Same as access_token
}
```

**Key Innovation:** The `access_token` IS the Response DID — it's self-validating via Archon resolution. No JWT required!

## Userinfo Response

```json
{
  "sub": "did:cid:bagaaiera...",  // User's DID
  "name": "Alice",                 // If available
  "response_did": "did:cid:..."    // The authentication response
}
```

## Integration Example

```javascript
// 1. Redirect user to authorization
const authUrl = new URL('http://localhost:3000/oauth/authorize');
authUrl.searchParams.set('client_id', 'my-app');
authUrl.searchParams.set('redirect_uri', 'http://localhost:4000/callback');
authUrl.searchParams.set('response_type', 'code');
authUrl.searchParams.set('scope', 'openid profile');
authUrl.searchParams.set('state', 'random-state-for-csrf');

window.location.href = authUrl.toString();

// 2. Handle callback (after user authenticates)
const code = new URLSearchParams(window.location.search).get('code');

// 3. Exchange code for token
const tokenResponse = await fetch('http://localhost:3000/oauth/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    grant_type: 'authorization_code',
    code,
    redirect_uri: 'http://localhost:4000/callback',
    client_id: 'my-app',
    client_secret: 'my-secret'
  })
});

const { access_token, responder_did } = await tokenResponse.json();

// 4. Use the token to get user info
const userinfo = await fetch('http://localhost:3000/oauth/userinfo', {
  headers: { 'Authorization': `Bearer ${access_token}` }
}).then(r => r.json());

console.log('Authenticated as:', userinfo.sub);  // User's DID
```

## Docker

```bash
docker build -t archon-oauth-server .
docker run -p 3000:3000 --env-file .env archon-oauth-server
```

## License

MIT

## Links

- **Archon Protocol:** https://archetech.com
- **Archon Technology:** https://archon.technology
- **Web Wallet:** https://wallet.archon.technology
