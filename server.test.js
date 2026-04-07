const request = require('supertest');
const app = require('./index'); // Imports your express app
const sqlite3 = require('sqlite3').verbose();

describe('JWKS Server Project 2 Tests', () => {
    
    // Test 1: Check if the JWKS endpoint returns the correct structure
    it('GET /.well-known/jwks.json should return a valid JWKS object', async () => {
        const res = await request(app).get('/.well-known/jwks.json');
        expect(res.statusCode).toEqual(200);
        expect(res.body).toHaveProperty('keys');
        expect(Array.isArray(res.body.keys)).toBe(true);
    });

    // Test 2: Check if /auth returns a JWT
    it('POST /auth should return a JWT token', async () => {
        const res = await request(app).post('/auth');
        expect(res.statusCode).toEqual(200);
        expect(res.body).toHaveProperty('token');
    });

    // Test 3: Check if /auth?expired=true returns a JWT
    it('POST /auth?expired=true should return a token', async () => {
        const res = await request(app).post('/auth?expired=true');
        expect(res.statusCode).toEqual(200);
        expect(res.body).toHaveProperty('token');
    });

    // Test 4: Check for Method Not Allowed on /auth
    it('GET /auth should return 405 Method Not Allowed', async () => {
        const res = await request(app).get('/auth');
        expect(res.statusCode).toEqual(405);
    });

    // Test 5: Verify the Database file exists
    it('should have created the SQLite database file', () => {
        const fs = require('fs');
        const dbExists = fs.existsSync('./totally_not_my_privateKeys.db');
        expect(dbExists).toBe(true);
    });
});