/**
 * OAuth 2.0 Provider for Archon Authentication
 * 
 * Key design: Uses DIDs as identifiers where possible
 * - client_id: Can be a DID (for Archon-native clients) or traditional string
 * - access_token: The Response DID itself (self-validating via Archon resolution)
 * - Authorization code: Maps to the verified response DID
 */

import { Router, Request, Response } from 'express';
import crypto from 'crypto';

// ============================================================================
// Types
// ============================================================================

export interface OAuthClient {
    client_id: string;          // Can be a DID or traditional client ID
    client_secret: string;
    name: string;
    redirect_uris: string[];
}

export interface OAuthConfig {
    hostUrl: string;
    walletUrl: string;
    clients?: OAuthClient[];
}

interface PendingAuth {
    client_id: string;
    redirect_uri: string;
    scope: string;
    state: string;
    challenge: string;
    created_at: number;
    complete?: boolean;
    code?: string;
    responder_did?: string;
}

interface AuthCode {
    code: string;
    client_id: string;
    redirect_uri: string;
    response_did: string;       // The Response DID from wallet
    responder_did: string;      // The user's DID who responded
    scope: string;
    created_at: number;
    expires_at: number;
}

interface AccessToken {
    response_did: string;       // Response DID IS the token (self-validating)
    client_id: string;
    responder_did: string;      // User's DID
    scope: string;
    created_at: number;
    expires_at: number;
}

// ============================================================================
// Storage (in-memory for demo; use DB in production)
// ============================================================================

const clients: Map<string, OAuthClient> = new Map();
const pendingAuths: Map<string, PendingAuth> = new Map();  // challenge -> pending auth
const authCodes: Map<string, AuthCode> = new Map();         // code -> auth code
const accessTokens: Map<string, AccessToken> = new Map();   // response_did -> token data

// ============================================================================
// Helpers
// ============================================================================

function generateCode(): string {
    return crypto.randomBytes(32).toString('base64url');
}

function isDID(str: string): boolean {
    return str.startsWith('did:');
}

// ============================================================================
// Client Registration
// ============================================================================

export function registerClient(client: OAuthClient): void {
    clients.set(client.client_id, client);
}

export function getClient(clientId: string): OAuthClient | undefined {
    return clients.get(clientId);
}

// ============================================================================
// OAuth Routes Factory
// ============================================================================

export function createOAuthRoutes(
    getKeymaster: () => any,
    config: OAuthConfig,
    getUserByDID?: (did: string) => Promise<any>
) {
    const keymaster = () => getKeymaster();
    const { hostUrl, walletUrl } = config;

    // Register any pre-configured clients
    if (config.clients) {
        for (const client of config.clients) {
            registerClient(client);
        }
    }

    const router = Router();

    // ========================================================================
    // GET /authorize
    // Authorization endpoint - initiates the flow
    // ========================================================================
    router.get('/authorize', async (req: Request, res: Response) => {
        try {
            const { 
                client_id, 
                redirect_uri, 
                response_type, 
                scope, 
                state 
            } = req.query;

            // Validate required params
            if (!client_id || !redirect_uri || response_type !== 'code') {
                return res.status(400).json({
                    error: 'invalid_request',
                    error_description: 'Missing required parameters. Need: client_id, redirect_uri, response_type=code'
                });
            }

            // Validate client
            const client = clients.get(client_id as string);
            if (!client) {
                if (isDID(client_id as string)) {
                    return res.status(400).json({
                        error: 'invalid_client',
                        error_description: 'Unknown client_id. DID clients must be pre-registered.'
                    });
                }
                return res.status(400).json({
                    error: 'invalid_client',
                    error_description: 'Unknown client_id'
                });
            }

            // Validate redirect_uri
            if (!client.redirect_uris.includes(redirect_uri as string)) {
                return res.status(400).json({
                    error: 'invalid_request',
                    error_description: 'Invalid redirect_uri'
                });
            }

            // Create Archon challenge
            const challenge = await keymaster().createChallenge({
                callback: `${hostUrl}/oauth/callback`
            });

            // Store pending authorization keyed by challenge
            pendingAuths.set(challenge, {
                client_id: client_id as string,
                redirect_uri: redirect_uri as string,
                scope: (scope as string) || 'openid profile',
                state: (state as string) || '',
                challenge,
                created_at: Date.now()
            });

            // Build wallet URL
            const challengeURL = `${walletUrl}?challenge=${challenge}`;

            // Return authorization page
            res.send(`
<!DOCTYPE html>
<html>
<head>
    <title>Sign in with Archon</title>
    <script src="https://cdn.jsdelivr.net/npm/qrcode@1.5.3/build/qrcode.min.js"></script>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; 
            background: #f5f5f5;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container {
            background: white;
            padding: 40px;
            border-radius: 16px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
            text-align: center;
            max-width: 400px;
        }
        h1 { font-size: 24px; margin-bottom: 8px; color: #1f2937; }
        .subtitle { color: #666; margin-bottom: 24px; }
        .client-name { color: #22c55e; font-weight: 600; }
        .qr-container { 
            margin: 24px auto;
            cursor: pointer;
        }
        .qr-container canvas {
            border-radius: 12px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }
        .open-wallet {
            display: inline-block;
            background: #22c55e;
            color: white;
            padding: 14px 28px;
            border-radius: 8px;
            text-decoration: none;
            font-weight: 600;
            margin: 16px 0;
            transition: background 0.2s;
        }
        .open-wallet:hover { background: #16a34a; }
        .challenge-did { 
            font-family: monospace; 
            font-size: 10px; 
            background: #f3f4f6; 
            padding: 12px; 
            border-radius: 8px;
            word-break: break-all;
            color: #888;
            margin-top: 16px;
        }
        .status { 
            color: #666; 
            font-size: 14px; 
            margin-top: 24px;
            padding-top: 16px;
            border-top: 1px solid #eee;
        }
        .spinner { animation: spin 1s linear infinite; display: inline-block; }
        @keyframes spin { to { transform: rotate(360deg); } }
        .error { color: #dc2626; margin-top: 16px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Sign in with Archon</h1>
        <p class="subtitle"><span class="client-name">${client.name}</span> wants to verify your identity</p>
        
        <a href="${challengeURL}" target="_blank" class="qr-container" title="Click to open in wallet">
            <canvas id="qr"></canvas>
        </a>
        
        <p><a href="${challengeURL}" target="_blank" class="open-wallet">Open Wallet</a></p>
        
        <p class="challenge-did">${challenge}</p>
        
        <p class="status" id="status"><span class="spinner">⏳</span> Waiting for wallet response...</p>
        <p class="error" id="error" style="display:none;"></p>
    </div>
    
    <script>
        QRCode.toCanvas(document.getElementById('qr'), '${challengeURL}', {
            width: 200,
            margin: 2,
            color: { dark: '#1f2937', light: '#ffffff' }
        });
        
        const pollInterval = setInterval(async () => {
            try {
                const res = await fetch('/oauth/poll?challenge=${encodeURIComponent(challenge)}');
                const data = await res.json();
                
                if (data.status === 'complete' && data.redirect) {
                    clearInterval(pollInterval);
                    document.getElementById('status').innerHTML = '✅ Authenticated! Redirecting...';
                    window.location.href = data.redirect;
                } else if (data.status === 'error') {
                    clearInterval(pollInterval);
                    document.getElementById('status').style.display = 'none';
                    document.getElementById('error').style.display = 'block';
                    document.getElementById('error').textContent = data.message || 'Authentication failed';
                }
            } catch (e) {
                console.error('Poll error:', e);
            }
        }, 2000);
        
        setTimeout(() => {
            clearInterval(pollInterval);
            document.getElementById('status').innerHTML = '⏱️ Session expired. Please refresh to try again.';
        }, 5 * 60 * 1000);
    </script>
</body>
</html>
            `);

        } catch (error: any) {
            console.error('OAuth authorize error:', error);
            res.status(500).json({ 
                error: 'server_error', 
                error_description: error.message 
            });
        }
    });

    // ========================================================================
    // POST /callback  
    // Receives response DID from wallet
    // ========================================================================
    router.post('/callback', async (req: Request, res: Response) => {
        try {
            const { response } = req.body;

            if (!response) {
                return res.status(400).json({ error: 'missing_response' });
            }

            const verify = await keymaster().verifyResponse(response, { retries: 10 });

            if (!verify.match) {
                return res.status(400).json({ 
                    error: 'invalid_response',
                    error_description: 'Response verification failed'
                });
            }

            const challenge = verify.challenge;
            const responderDID = verify.responder;

            const pending = pendingAuths.get(challenge);
            if (!pending) {
                return res.status(400).json({ 
                    error: 'invalid_challenge',
                    error_description: 'Challenge not found or expired'
                });
            }

            const code = generateCode();
            
            authCodes.set(code, {
                code,
                client_id: pending.client_id,
                redirect_uri: pending.redirect_uri,
                response_did: response,
                responder_did: responderDID,
                scope: pending.scope,
                created_at: Date.now(),
                expires_at: Date.now() + (10 * 60 * 1000)
            });

            pending.complete = true;
            pending.code = code;
            pending.responder_did = responderDID;
            pendingAuths.set(challenge, pending);

            res.json({ 
                ok: true, 
                message: 'Response verified',
                responder: responderDID
            });

        } catch (error: any) {
            console.error('OAuth callback error:', error);
            res.status(500).json({ 
                error: 'server_error', 
                error_description: error.message 
            });
        }
    });

    // ========================================================================
    // GET /callback
    // Alternative: wallet redirects here with response in query
    // ========================================================================
    router.get('/callback', async (req: Request, res: Response) => {
        try {
            const { response } = req.query;

            if (!response || typeof response !== 'string') {
                return res.status(400).send('Missing response parameter');
            }

            const verify = await keymaster().verifyResponse(response, { retries: 10 });

            if (!verify.match) {
                return res.status(400).send('Response verification failed');
            }

            const challenge = verify.challenge;
            const responderDID = verify.responder;

            const pending = pendingAuths.get(challenge);
            if (!pending) {
                return res.status(400).send('Challenge not found or expired');
            }

            const code = generateCode();

            authCodes.set(code, {
                code,
                client_id: pending.client_id,
                redirect_uri: pending.redirect_uri,
                response_did: response,
                responder_did: responderDID,
                scope: pending.scope,
                created_at: Date.now(),
                expires_at: Date.now() + (10 * 60 * 1000)
            });

            const redirectUrl = new URL(pending.redirect_uri);
            redirectUrl.searchParams.set('code', code);
            if (pending.state) {
                redirectUrl.searchParams.set('state', pending.state);
            }

            pendingAuths.delete(challenge);

            res.redirect(redirectUrl.toString());

        } catch (error: any) {
            console.error('OAuth callback GET error:', error);
            res.status(500).send('Server error: ' + error.message);
        }
    });

    // ========================================================================
    // GET /poll
    // Client polls to check if auth is complete
    // ========================================================================
    router.get('/poll', async (req: Request, res: Response) => {
        try {
            const { challenge } = req.query;

            if (!challenge || typeof challenge !== 'string') {
                return res.json({ status: 'error', message: 'Missing challenge' });
            }

            const pending = pendingAuths.get(challenge);

            if (!pending) {
                return res.json({ status: 'error', message: 'Challenge not found' });
            }

            if (pending.complete && pending.code) {
                const redirectUrl = new URL(pending.redirect_uri);
                redirectUrl.searchParams.set('code', pending.code);
                if (pending.state) {
                    redirectUrl.searchParams.set('state', pending.state);
                }

                pendingAuths.delete(challenge);

                return res.json({ 
                    status: 'complete', 
                    redirect: redirectUrl.toString()
                });
            }

            res.json({ status: 'pending' });

        } catch (error: any) {
            console.error('OAuth poll error:', error);
            res.json({ status: 'error', message: error.message });
        }
    });

    // ========================================================================
    // POST /token
    // Exchange authorization code for access token
    // ========================================================================
    router.post('/token', async (req: Request, res: Response) => {
        try {
            const { 
                grant_type, 
                code, 
                redirect_uri, 
                client_id, 
                client_secret 
            } = req.body;

            if (grant_type !== 'authorization_code') {
                return res.status(400).json({
                    error: 'unsupported_grant_type',
                    error_description: 'Only authorization_code grant is supported'
                });
            }

            const client = clients.get(client_id);
            if (!client || client.client_secret !== client_secret) {
                return res.status(401).json({
                    error: 'invalid_client',
                    error_description: 'Invalid client credentials'
                });
            }

            const authCode = authCodes.get(code);
            if (!authCode) {
                return res.status(400).json({
                    error: 'invalid_grant',
                    error_description: 'Invalid or expired authorization code'
                });
            }

            if (authCode.redirect_uri !== redirect_uri) {
                return res.status(400).json({
                    error: 'invalid_grant',
                    error_description: 'redirect_uri mismatch'
                });
            }

            if (Date.now() > authCode.expires_at) {
                authCodes.delete(code);
                return res.status(400).json({
                    error: 'invalid_grant',
                    error_description: 'Authorization code expired'
                });
            }

            // The access token IS the Response DID (self-validating!)
            const accessToken = authCode.response_did;
            const expiresIn = 3600;

            accessTokens.set(accessToken, {
                response_did: authCode.response_did,
                client_id: authCode.client_id,
                responder_did: authCode.responder_did,
                scope: authCode.scope,
                created_at: Date.now(),
                expires_at: Date.now() + (expiresIn * 1000)
            });

            authCodes.delete(code);

            res.json({
                access_token: accessToken,
                token_type: 'Bearer',
                expires_in: expiresIn,
                scope: authCode.scope,
                responder_did: authCode.responder_did,
                response_did: authCode.response_did
            });

        } catch (error: any) {
            console.error('OAuth token error:', error);
            res.status(500).json({
                error: 'server_error',
                error_description: error.message
            });
        }
    });

    // ========================================================================
    // GET /userinfo
    // Returns user information for the authenticated user
    // ========================================================================
    router.get('/userinfo', async (req: Request, res: Response) => {
        try {
            const authHeader = req.headers.authorization;
            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                return res.status(401).json({
                    error: 'invalid_token',
                    error_description: 'Missing or invalid Authorization header'
                });
            }

            const token = authHeader.substring(7);
            const tokenData = accessTokens.get(token);
            
            if (!tokenData) {
                return res.status(401).json({
                    error: 'invalid_token',
                    error_description: 'Token not found or expired'
                });
            }

            if (Date.now() > tokenData.expires_at) {
                accessTokens.delete(token);
                return res.status(401).json({
                    error: 'invalid_token',
                    error_description: 'Token expired'
                });
            }

            const userinfo: any = {
                sub: tokenData.responder_did,
            };

            if (getUserByDID) {
                const user = await getUserByDID(tokenData.responder_did);
                if (user) {
                    if (user.name) userinfo.name = user.name;
                    if (user.email) userinfo.email = user.email;
                }
            }

            userinfo.response_did = tokenData.response_did;

            res.json(userinfo);

        } catch (error: any) {
            console.error('OAuth userinfo error:', error);
            res.status(500).json({
                error: 'server_error',
                error_description: error.message
            });
        }
    });

    // ========================================================================
    // GET /.well-known/openid-configuration
    // OIDC Discovery document
    // ========================================================================
    router.get('/.well-known/openid-configuration', (req: Request, res: Response) => {
        res.json({
            issuer: hostUrl,
            authorization_endpoint: `${hostUrl}/oauth/authorize`,
            token_endpoint: `${hostUrl}/oauth/token`,
            userinfo_endpoint: `${hostUrl}/oauth/userinfo`,
            response_types_supported: ['code'],
            grant_types_supported: ['authorization_code'],
            subject_types_supported: ['public'],
            id_token_signing_alg_values_supported: ['none'],
            scopes_supported: ['openid', 'profile'],
            claims_supported: ['sub', 'name', 'response_did'],
            archon_challenge_endpoint: `${hostUrl}/oauth/authorize`,
            archon_callback_endpoint: `${hostUrl}/oauth/callback`,
        });
    });

    return router;
}

// ============================================================================
// Token Validation Helper (for resource servers)
// ============================================================================

export function validateToken(token: string): AccessToken | null {
    const tokenData = accessTokens.get(token);
    if (!tokenData) return null;
    if (Date.now() > tokenData.expires_at) {
        accessTokens.delete(token);
        return null;
    }
    return tokenData;
}

export default { createOAuthRoutes, registerClient, getClient, validateToken };
