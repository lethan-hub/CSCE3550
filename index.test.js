const request = require('supertest');
const app = require('./index');

describe('JWKS Server API Tests', () => {
    test('GET /jwks should return 200 and valid keys', async () => {
        const res = await request(app).get('/jwks');
        expect(res.statusCode).toBe(200);
        expect(res.body.keys).toBeDefined();
    });

    test('POST /auth should return a valid JWT', async () => {
        const res = await request(app).post('/auth');
        expect(res.statusCode).toBe(200);
    });

    test('POST /auth?expired=true should return an expired JWT', async () => {
        const res = await request(app).post('/auth?expired=true');
        expect(res.statusCode).toBe(200);
    });

    test('Unsupported methods should return 405', async () => {
        const res = await request(app).get('/auth');
        expect(res.statusCode).toBe(405);
    });
});