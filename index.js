const express = require('express');
const jwt = require('jsonwebtoken');
const NodeRSA = require('node-rsa');

const app = express();
app.use(express.json());

let keys = [];

// Requirement 2.2: Helper to convert Buffer/Number to Base64URL for JWKS compliance
const toBase64Url = (input) => {
    let buffer;
    if (Buffer.isBuffer(input)) {
        buffer = input;
    } else if (typeof input === 'number') {
        // Essential: Convert exponent numbers to a hex buffer to ensure proper JWKS encoding
        let hex = input.toString(16);
        if (hex.length % 2 !== 0) hex = '0' + hex;
        buffer = Buffer.from(hex, 'hex');
    } else {
        buffer = Buffer.from(input);
    }
    return buffer.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
};

/**
 * Requirement 1.1: RSA Key Generation
 * Requirement 1.2: Associate unique kid and expiry timestamp
 */
function generateKey(isExpired = false) {
    const key = new NodeRSA({ b: 2048 });
    const components = key.exportKey('components');
    const kid = Math.random().toString(36).substring(7);
    
    // Set expiry based on current time
    const expiresAt = isExpired 
        ? Math.floor(Date.now() / 1000) - 3600 
        : Math.floor(Date.now() / 1000) + 3600;

    const keyPair = {
        kid,
        n: toBase64Url(components.n),
        e: toBase64Url(components.e),
        privateKey: key.exportKey('private'),
        expiresAt
    };
    keys.push(keyPair);
    return keyPair;
}

// Pre-generate initial valid and expired keys for testing
generateKey(false);
generateKey(true);

/**
 * Requirement 2.2: RESTful JWKS endpoint
 * Only serves unexpired keys
 */
app.get('/.well-known/jwks.json', (req, res) => {
    const validKeys = keys
        .filter(k => k.expiresAt > Math.floor(Date.now() / 1000))
        .map(k => ({
            kid: k.kid,
            kty: 'RSA',
            alg: 'RS256',
            use: 'sig',
            n: k.n,
            e: k.e
        }));
    res.json({ keys: validKeys });
});

// Also support /jwks for backward compatibility
app.get('/jwks', (req, res) => {
    const validKeys = keys
        .filter(k => k.expiresAt > Math.floor(Date.now() / 1000))
        .map(k => ({
            kid: k.kid,
            kty: 'RSA',
            alg: 'RS256',
            use: 'sig',
            n: k.n,
            e: k.e
        }));
    res.json({ keys: validKeys });
});

/**
 * Requirement 2.3: /auth endpoint
 * Handles ?expired=true query parameter to issue JWTs with expired keys
 */
app.post('/auth', (req, res) => {
    const expiredRequested = req.query.expired === 'true';
    const now = Math.floor(Date.now() / 1000);
    
    // Select the appropriate key pair based on the query parameter
    const keyPair = expiredRequested 
        ? keys.find(k => k.expiresAt < now)
        : keys.find(k => k.expiresAt > now);

    if (!keyPair) {
        return res.status(404).send('Key not found');
    }

    // Use manual payload to ensure 'exp' is definitely in the past for expired requests
    const payload = {
        user: 'username',
        iat: now,
        exp: expiredRequested ? now - 3600 : now + 3600
    };

    // Sign JWT and include kid in header for identification
    const token = jwt.sign(payload, keyPair.privateKey, {
        algorithm: 'RS256',
        header: { kid: keyPair.kid }
    });
    
    res.json({ token: token });
});

// Handle other HTTP methods on /auth with 405
app.get('/auth', (req, res) => {
    res.status(405).send('Method Not Allowed');
});

app.put('/auth', (req, res) => {
    res.status(405).send('Method Not Allowed');
});

app.delete('/auth', (req, res) => {
    res.status(405).send('Method Not Allowed');
});

app.patch('/auth', (req, res) => {
    res.status(405).send('Method Not Allowed');
});

// Export before starting server
module.exports = app;

// Only start server if run directly
if (require.main === module) {
    const PORT = process.env.PORT || 8080;
    app.listen(PORT, () => {
        console.log(`JWKS Server running at http://localhost:${PORT}`);
    });
}