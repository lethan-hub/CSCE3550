const express = require('express');
const jwt = require('jsonwebtoken');
const NodeRSA = require('node-rsa');
const sqlite3 = require('sqlite3').verbose(); // Requirement: sqlite3

const app = express();
app.use(express.json());

// 1. DATABASE SETUP
// Requirement: Create/open a SQLite DB file named 'totally_not_my_privateKeys.db'
const db = new sqlite3.Database('./totally_not_my_privateKeys.db');

// Requirement: Define the table schema
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS keys(
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    )`);
});

// Base64URL is used with JWKS as it converts the characters to ensure information is safe over the internet
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
    
    
    const privateKeyPem = key.exportKey('private');
    // Set an expiration time
    const expiresAt = isExpired 
        ? Math.floor(Date.now() / 1000) - 3600  
        : Math.floor(Date.now() / 1000) + 3600; 

    
    db.run(`INSERT INTO keys (key, exp) VALUES (?, ?)`, [privateKeyPem, expiresAt]);
}

// Used for testing
generateKey(false);
generateKey(true);

// JWKS is used to be used publicly and only obtains keys that expire in the future
app.get('/.well-known/jwks.json', (req, res) => {
    const now = Math.floor(Date.now() / 1000);
    
    // Checks all the keys that have not expired
    db.all("SELECT * FROM keys WHERE exp > ?", [now], (err, rows) => {
        // Checks for errors and sends a message
        if (err) return res.status(500).send("Database error");

        const jwks = rows.map(row => {
            const key = new NodeRSA(row.key);
            const components = key.exportKey('components');
            // Formats the JSON
            return {
                kid: row.kid.toString(),
                kty: 'RSA',
                alg: 'RS256',
                use: 'sig',
                n: toBase64Url(components.n),
                e: toBase64Url(components.e)
            };
        });
        res.json({ keys: jwks });
    });
});

// This /auth section allows the JSON Web Token to make sure the POST request is valid and or passed
app.post('/auth', (req, res) => {
    const expiredRequested = req.query.expired === 'true';
    const now = Math.floor(Date.now() / 1000);
    
    // Figures out which one is expired and uses the non expired one
    const query = expiredRequested 
        ? "SELECT * FROM keys WHERE exp <= ? LIMIT 1" 
        : "SELECT * FROM keys WHERE exp > ? LIMIT 1";

    db.get(query, [now], (err, row) => {
        if (err || !row) {
            return res.status(404).send('Key not found');
        }

        // Checks if the date is actually expired
        const payload = {
            user: 'username',
            iat: now,
            exp: expiredRequested ? now - 3600 : now + 3600
        };

        // Creation of JWT to provide a unique ID for indetification
        const token = jwt.sign(payload, row.key, {
            algorithm: 'RS256',
            header: { kid: row.kid.toString() }
        });
        
        res.json({ token: token });
    });
});

// Handles all other HTTP methods
app.all('/auth', (req, res) => {
    if (req.method !== 'POST') {
        res.status(405).send('Method Not Allowed');
    }
});

// Only starts if it is ran directly
if (require.main === module) {
    const PORT = process.env.PORT || 8080;
    app.listen(PORT, () => {
        console.log(`JWKS Server with SQLite running at http://localhost:${PORT}`);
    });
}

// Exports before starting server
module.exports = app;