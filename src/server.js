const app = require('./app');
const { initSchemaWithRetry } = require('./db/migrations');
const { validateAIConfig } = require('./lib/ai');
const { pool } = require('./db/pool');
const { markShuttingDown } = require('./routes/health');

const PORT = process.env.PORT || 3000;

initSchemaWithRetry()
  .then(() => validateAIConfig())
  .then(() => {
    const server = app.listen(PORT, () => {
      console.log(`Schautrack listening on port ${PORT}`);
    });

    // Graceful shutdown handler
    const gracefulShutdown = (signal) => {
      console.log(`Received ${signal}. Starting graceful shutdown...`);
      markShuttingDown();
      server.close(async (err) => {
        if (err) {
          console.error('Error closing server:', err);
          process.exit(1);
        }
        
        console.log('HTTP server closed.');
        
        try {
          await pool.end();
          console.log('Database pool closed.');
          console.log('Graceful shutdown completed.');
          process.exit(0);
        } catch (dbErr) {
          console.error('Error closing database pool:', dbErr);
          process.exit(1);
        }
      });

      // Force shutdown after 30 seconds
      setTimeout(() => {
        console.error('Forced shutdown after timeout');
        process.exit(1);
      }, 30000);
    };

    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));
  })
  .catch(err => {
    console.error('Startup failed:', err);
    process.exit(1);
  });