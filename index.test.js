

const request = require('supertest'); // Hands the HTTP requests
const app = require('./index'); // Imports the index.js file

// Tests are here
describe('JWKS Server API Tests', () => {
    // Checks if public key is accessible
    test('GET /jwks should return 200 and valid keys', async () => {
        const res = await request(app).get('/jwks');
        expect(res.statusCode).toBe(200);
        expect(res.body.keys).toBeDefined();
    });

// Ensures that the server can obtain a valid token
    test('POST /auth should return a valid JWT', async () => {
        const res = await request(app).post('/auth');
        expect(res.statusCode).toBe(200);
    });

// Occurs whenever a user inputs an expired token
    test('POST /auth?expired=true should return an expired JWT', async () => {
        const res = await request(app).post('/auth?expired=true');
        expect(res.statusCode).toBe(200);
    });

// Error case to handle wrong HTTP requests
    test('Unsupported methods should return 405', async () => {
        const res = await request(app).get('/auth');
        expect(res.statusCode).toBe(405);
    });

});
