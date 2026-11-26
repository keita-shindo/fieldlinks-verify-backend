const express = require('express');
const { Pool } = require('pg');

const app = express();
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

app.get('/healthz', (req, res) => {
  res.status(200).json({ status: 'ok' });
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
