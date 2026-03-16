const request = require('supertest');
const app = require('./index'); // Imports your express app
const sqlite3 = require('sqlite3').verbose();

describe('JWKS Server Project 2 Tests', () => {
    
   
  // Checks if the JWKS returns the correct format
    it('GET /.well-known/jwks.json should return a valid JWKS object', async () => {
        const res = await request(app).get('/.well-known/jwks.json');
        expect(res.statusCode).toEqual(200);
        expect(res.body).toHaveProperty('keys');
        expect(Array.isArray(res.body.keys)).toBe(true);
    });

    // Checks if /auth returns a JWT
    it('POST /auth should return a JWT token', async () => {
        const res = await request(app).post('/auth');
        expect(res.statusCode).toEqual(200);
        expect(res.body).toHaveProperty('token');
    });

    
  // Check if the /auth?expired=true returns a JWT and not expired
    it('POST /auth?expired=true should return a token', async () => {
        const res = await request(app).post('/auth?expired=true');
        expect(res.statusCode).toEqual(200);
        expect(res.body).toHaveProperty('token');
    });

    
  // Check the /auth method to make sure it does not allow
    it('GET /auth should return 405 Method Not Allowed', async () => {
        const res = await request(app).get('/auth');
        expect(res.statusCode).toEqual(405);
    });

    
  // Check that the database files exist
    it('should have created the SQLite database file', () => {
        const fs = require('fs');
        const dbExists = fs.existsSync('./totally_not_my_privateKeys.db');
        expect(dbExists).toBe(true);
    });
});
