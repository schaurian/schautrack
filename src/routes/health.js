const express = require('express');
const { pool } = require('../db/pool');

const router = express.Router();

// Health check endpoint for app verification
router.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({
      app: 'schautrack',
      status: 'ok',
      version: process.env.BUILD_VERSION || 'dev'
    });
  } catch {
    res.status(503).json({
      app: 'schautrack',
      status: 'error',
      version: process.env.BUILD_VERSION || 'dev'
    });
  }
});

module.exports = router;