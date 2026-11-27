const express = require('express');
const { Pool } = require('pg');
const { createRemoteJWKSet, jwtVerify } = require('jose');
const { BlobServiceClient, generateBlobSASQueryParameters, BlobSASPermissions } = require('@azure/storage-blob');

const CONTAINER_NAME = 'test-files';
const blobServiceClient = BlobServiceClient.fromConnectionString(process.env.AZURE_STORAGE_CONNECTION_STRING);

const ISSUER = 'https://c94aca5e-27ab-4cdb-b764-b6d4baa28749.ciamlogin.com/c94aca5e-27ab-4cdb-b764-b6d4baa28749/v2.0';
const JWKS_URI = 'https://fieldlinksauthpoc.ciamlogin.com/c94aca5e-27ab-4cdb-b764-b6d4baa28749/discovery/v2.0/keys';
const EXPECTED_AUDIENCE = 'b4bc664b-5c2c-4124-8bf9-f6c15a5fcffb';

const jwks = createRemoteJWKSet(new URL(JWKS_URI));

const app = express();
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

app.get('/healthz', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

app.get('/verify-token', async (req, res) => {
  const authHeader = req.get('authorization') || '';
  const match = authHeader.match(/^Bearer (.+)$/i);
  if (!match) {
    return res.status(401).json({ valid: false, error: 'missing or malformed Authorization header' });
  }
  const token = match[1];

  try {
    const { payload } = await jwtVerify(token, jwks, { issuer: ISSUER });

    const aud = payload.aud;
    const audOk = aud === EXPECTED_AUDIENCE || aud === `api://${EXPECTED_AUDIENCE}`;
    if (!audOk) {
      return res.status(401).json({ valid: false, error: `unexpected audience: ${aud}` });
    }

    res.status(200).json({
      valid: true,
      issuer: payload.iss,
      audience: payload.aud,
      scp: payload.scp,
      exp: payload.exp,
      sub: payload.sub,
    });
  } catch (err) {
    res.status(401).json({ valid: false, error: err.message });
  }
});

app.get('/debug/outbound-ip', async (req, res) => {
  try {
    const r = await fetch('https://api.ipify.org?format=json');
    const data = await r.json();
    res.status(200).json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/blob-sas', async (req, res) => {
  if (req.get('x-admin-key') !== process.env.ADMIN_KEY) {
    return res.status(401).json({ error: 'unauthorized' });
  }

  const filename = req.query.filename;
  const mode = req.query.mode === 'write' ? 'write' : 'read';
  if (!filename) {
    return res.status(400).json({ error: 'filename query param is required' });
  }

  try {
    const containerClient = blobServiceClient.getContainerClient(CONTAINER_NAME);
    const blobClient = containerClient.getBlobClient(filename);

    const permissions = new BlobSASPermissions();
    if (mode === 'write') {
      permissions.write = true;
      permissions.create = true;
    } else {
      permissions.read = true;
    }

    const expiresOn = new Date(Date.now() + 10 * 60 * 1000);

    const sasToken = generateBlobSASQueryParameters(
      {
        containerName: CONTAINER_NAME,
        blobName: filename,
        permissions,
        expiresOn,
      },
      blobServiceClient.credential
    ).toString();

    res.status(200).json({
      sasUrl: `${blobClient.url}?${sasToken}`,
      mode,
      expiresOn,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/admin/apply-sql', async (req, res) => {
  if (req.get('x-admin-key') !== process.env.ADMIN_KEY) {
    return res.status(401).json({ error: 'unauthorized' });
  }

  const { sql } = req.body || {};
  if (!sql || typeof sql !== 'string') {
    return res.status(400).json({ error: 'sql (string) is required in the request body' });
  }

  try {
    const result = await pool.query(sql);
    res.status(200).json({
      success: true,
      rowCount: result.rowCount,
      rows: result.rows,
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

const port = process.env.PORT || 8080;
app.listen(port, () => {
  console.log(`fieldlinks-verify-backend listening on port ${port}`);
});
