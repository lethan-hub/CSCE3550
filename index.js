const express = require('express');
const jwt = require('jsonwebtoken');
const NodeRSA = require('node-rsa');

const app = express();
app.use(express.json());

let keys = [];

// Base64URL is used with the assistance of JWKS as it encodes the characters to ensure information is safe over the internet
const toBase64Url = (input) => {
    let buffer;
    if (Buffer.isBuffer(input)) {
        buffer = input;
    } else if (typeof input === 'number') {
        // Converts exponent numbers to a hex buffer to ensure encoding is complete throughout the process
        let hex = input.toString(16);
        if (hex.length % 2 !== 0) hex = '0' + hex;
        buffer = Buffer.from(hex, 'hex');
    } else {
        buffer = Buffer.from(input);
    }
    return buffer.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
};

 // This is used for the RSA Key Generation and it provides a unique kid(which is an ID) and a expiration date
 
function generateKey(isExpired = false) {
    // Generates a 2048 RSA key pair
    const key = new NodeRSA({ b: 2048 });
    const components = key.exportKey('components');
    const kid = Math.random().toString(36).substring(7);
    
    // Set an expiration time
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

// Used for testing
generateKey(false);
generateKey(true);

// JWKS is used to be used publicly and only obtains keys that expire in the future
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

// It allows jwks to work with older versions
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

// This the /auth section that allows the JSON Web Token to make sure the POST request is passed
app.post('/auth', (req, res) => {
    const expiredRequested = req.query.expired === 'true';
    const now = Math.floor(Date.now() / 1000);
    
    // Select the appropriate key pair based on if it is expired or not
    const keyPair = expiredRequested 
        ? keys.find(k => k.expiresAt < now)
        : keys.find(k => k.expiresAt > now);

    if (!keyPair) {
        return res.status(404).send('Key not found');
    }

    // Check if the date is actually expired
    const payload = {
        user: 'username',
        iat: now,
        exp: expiredRequested ? now - 3600 : now + 3600
    };

    // Creation of JWT to provide a unique ID for identitication
    const token = jwt.sign(payload, keyPair.privateKey, {
        algorithm: 'RS256',
        header: { kid: keyPair.kid }
    });
    
    res.json({ token: token });
});

// Handle other HTTP methods
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
