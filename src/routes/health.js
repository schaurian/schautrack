const express = require('express');
const { pool } = require('../db/pool');

const router = express.Router();

let shuttingDown = false;

const markShuttingDown = () => { shuttingDown = true; };

// Health check endpoint for app verification
router.get('/health', async (req, res) => {
  if (shuttingDown) {
    return res.status(503).json({
      app: 'schautrack',
      status: 'shutting_down',
      version: process.env.BUILD_VERSION || 'dev'
    });
  }
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
module.exports.markShuttingDown = markShuttingDown;
