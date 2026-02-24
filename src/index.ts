/**
 * Archon OAuth Server
 * 
 * A standalone OAuth 2.0 Authorization Server using Archon DID authentication.
 * 
 * Key Features:
 * - OAuth 2.0 Authorization Code flow
 * - Uses Archon challenge/response for authentication
 * - Response DID as access_token (self-validating)
 * - OIDC-compatible discovery endpoint
 */

import express from 'express';
import session from 'express-session';
import morgan from 'morgan';
import cors from 'cors';
import dotenv from 'dotenv';

// @ts-ignore - Archon packages
import CipherNode from '@didcid/cipher/node';
// @ts-ignore
import GatekeeperClient from '@didcid/gatekeeper/client';
// @ts-ignore
import Keymaster from '@didcid/keymaster';
// @ts-ignore
import WalletJson from '@didcid/keymaster/wallet/json';

import { createOAuthRoutes, registerClient, OAuthClient } from './oauth.js';

dotenv.config();

// ============================================================================
// Configuration
// ============================================================================

const PORT = Number(process.env.PORT) || 3000;
const HOST_URL = process.env.HOST_URL || `http://localhost:${PORT}`;
const GATEKEEPER_URL = process.env.GATEKEEPER_URL || 'http://localhost:4224';
const WALLET_URL = process.env.WALLET_URL || 'https://wallet.archon.technology';
const WALLET_PASSPHRASE = process.env.WALLET_PASSPHRASE;
const SESSION_SECRET = process.env.SESSION_SECRET || 'archon-oauth-secret-change-me';

// ============================================================================
// Initialize Express
// ============================================================================

const app = express();

app.use(morgan('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// CORS configuration
const corsOptions = {
    origin: process.env.CORS_ORIGIN || '*',
    methods: ['GET', 'POST', 'OPTIONS'],
    credentials: true,
    optionsSuccessStatus: 200
};

app.use(cors(corsOptions));

// ============================================================================
// Keymaster Initialization
// ============================================================================

let keymaster: any;

async function initKeymaster(): Promise<void> {
    if (!WALLET_PASSPHRASE) {
        console.error('Error: WALLET_PASSPHRASE environment variable not set');
        process.exit(1);
    }

    const gatekeeper = new GatekeeperClient();
    await gatekeeper.connect({
        url: GATEKEEPER_URL,
        waitUntilReady: true,
        intervalSeconds: 5,
        chatty: true,
    });

    const wallet = new WalletJson();
    const cipher = new CipherNode();
    
    keymaster = new Keymaster({
        gatekeeper,
        wallet,
        cipher,
        passphrase: WALLET_PASSPHRASE,
    });

    // Create default identity if needed
    const ids = await keymaster.listIds();
    if (ids.length === 0) {
        await keymaster.createId('oauth-server');
        console.log('Created default identity: oauth-server');
    }

    console.log(`Connected to gatekeeper at ${GATEKEEPER_URL}`);
}

// ============================================================================
// Routes
// ============================================================================

// Health check
app.get('/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        service: 'archon-oauth-server',
        version: '0.1.0'
    });
});

// Info endpoint
app.get('/', (req, res) => {
    res.json({
        name: 'Archon OAuth Server',
        description: 'OAuth 2.0 Authorization Server using Archon DID authentication',
        endpoints: {
            authorize: `${HOST_URL}/oauth/authorize`,
            token: `${HOST_URL}/oauth/token`,
            userinfo: `${HOST_URL}/oauth/userinfo`,
            discovery: `${HOST_URL}/oauth/.well-known/openid-configuration`
        },
        documentation: 'https://github.com/Flaxscrip/archon-oauth-server'
    });
});

// ============================================================================
// Client Registration API
// ============================================================================

// Register a new OAuth client
app.post('/api/clients', (req, res) => {
    try {
        const { client_id, client_secret, name, redirect_uris } = req.body;

        if (!client_id || !client_secret || !name || !redirect_uris) {
            return res.status(400).json({
                error: 'invalid_request',
                error_description: 'Missing required fields: client_id, client_secret, name, redirect_uris'
            });
        }

        const client: OAuthClient = {
            client_id,
            client_secret,
            name,
            redirect_uris: Array.isArray(redirect_uris) ? redirect_uris : [redirect_uris]
        };

        registerClient(client);

        res.status(201).json({
            ok: true,
            message: 'Client registered',
            client_id
        });

    } catch (error: any) {
        res.status(500).json({
            error: 'server_error',
            error_description: error.message
        });
    }
});

// ============================================================================
// Start Server
// ============================================================================

async function start(): Promise<void> {
    try {
        // Initialize Keymaster
        await initKeymaster();

        // Mount OAuth routes
        const oauthRouter = createOAuthRoutes(
            () => keymaster,
            {
                hostUrl: HOST_URL,
                walletUrl: WALLET_URL,
                clients: [
                    // Demo client for testing
                    {
                        client_id: 'demo-client',
                        client_secret: 'demo-secret',
                        name: 'Demo Application',
                        redirect_uris: [
                            'http://localhost:3001/callback',
                            'http://localhost:3001/oauth/callback',
                            'http://localhost:4000/callback',
                            'http://localhost:4000/oauth/callback',
                        ]
                    }
                ]
            }
        );

        app.use('/oauth', oauthRouter);

        // Start listening
        app.listen(PORT, '0.0.0.0', () => {
            console.log('');
            console.log('╔═══════════════════════════════════════════════════════╗');
            console.log('║         Archon OAuth Server                           ║');
            console.log('╠═══════════════════════════════════════════════════════╣');
            console.log(`║  Server:     ${HOST_URL.padEnd(40)}║`);
            console.log(`║  Gatekeeper: ${GATEKEEPER_URL.padEnd(40)}║`);
            console.log(`║  Wallet UI:  ${WALLET_URL.padEnd(40)}║`);
            console.log('╠═══════════════════════════════════════════════════════╣');
            console.log('║  Endpoints:                                           ║');
            console.log(`║    /oauth/authorize     - Authorization               ║`);
            console.log(`║    /oauth/token         - Token exchange              ║`);
            console.log(`║    /oauth/userinfo      - User info                   ║`);
            console.log(`║    /oauth/.well-known/openid-configuration            ║`);
            console.log('╚═══════════════════════════════════════════════════════╝');
            console.log('');
        });

    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
}

// Handle graceful shutdown
process.on('SIGINT', () => {
    console.log('\nShutting down...');
    process.exit(0);
});

process.on('uncaughtException', (error) => {
    console.error('Uncaught exception:', error);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled rejection at:', promise, 'reason:', reason);
});

// Start the server
start();
