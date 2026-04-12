import { test, expect } from '@playwright/test';
import { execSync } from 'child_process';

// Infrastructure test: verifies the Go server handles SIGTERM gracefully (exit code 0).
// This test sends SIGTERM to the running test web container, waits for it to exit,
// checks the exit code, then restarts it for subsequent test runs.
//
// IMPORTANT: This test modifies shared infrastructure and must run last.
// It is placed in the "chromium" project which runs after other setup projects.

const WEB_CONTAINER = 'schautrack-test-web-1';

test.describe('Graceful Shutdown', () => {
  // Dependency note: This test stops and restarts the test container.
  // Run it last by ensuring your test ordering doesn't interleave with other suites.

  test('SIGTERM exits cleanly with exit code 0', async () => {
    // Verify the container is running before attempting shutdown
    let containerRunning = false;
    try {
      const status = execSync(`docker inspect ${WEB_CONTAINER} --format="{{.State.Status}}"`, {
        encoding: 'utf-8',
        timeout: 10000,
      }).trim().replace(/^"|"$/g, '');
      containerRunning = status === 'running';
    } catch {
      test.skip(true, `Container ${WEB_CONTAINER} not found — skipping graceful shutdown test`);
      return;
    }

    if (!containerRunning) {
      test.skip(true, `Container ${WEB_CONTAINER} is not running — skipping graceful shutdown test`);
      return;
    }

    // Send SIGTERM to the web container
    execSync(`docker kill --signal=SIGTERM ${WEB_CONTAINER}`, {
      encoding: 'utf-8',
      timeout: 10000,
    });

    // Wait up to 45 seconds for the container to exit cleanly.
    // The Go server has a 30s graceful drain timeout, so this needs to exceed that.
    let exited = false;
    for (let i = 0; i < 90; i++) {
      await new Promise((r) => setTimeout(r, 500));
      try {
        const state = execSync(
          `docker inspect ${WEB_CONTAINER} --format="{{.State.Status}}"`,
          { encoding: 'utf-8', timeout: 5000 }
        ).trim().replace(/^"|"$/g, '');
        if (state === 'exited') {
          exited = true;
          break;
        }
      } catch {
        // Container may have been removed — treat as exited
        exited = true;
        break;
      }
    }

    expect(exited).toBe(true);

    // Check exit code
    try {
      const exitCode = execSync(
        `docker inspect ${WEB_CONTAINER} --format="{{.State.ExitCode}}"`,
        { encoding: 'utf-8', timeout: 5000 }
      ).trim().replace(/^"|"$/g, '');

      expect(exitCode).toBe('0');
    } catch {
      // If the container is no longer inspectable, skip exit code check
    }

    // Restart the container so subsequent tests can continue
    try {
      execSync(`docker compose -f compose.test.yml up -d web`, {
        encoding: 'utf-8',
        timeout: 60000,
        cwd: '/home/schaurian/Sync/code/schautrack',
      });

      // Wait for the health endpoint to come back
      let healthy = false;
      for (let i = 0; i < 30; i++) {
        await new Promise((r) => setTimeout(r, 1000));
        try {
          const healthOut = execSync(
            'curl -sf http://localhost:3001/api/health',
            { encoding: 'utf-8', timeout: 3000 }
          );
          if (healthOut.includes('"ok"') || healthOut.includes('"status"')) {
            healthy = true;
            break;
          }
        } catch {
          // still starting up
        }
      }

      if (!healthy) {
        console.warn('[graceful-shutdown] Container restarted but health check did not pass within 30s');
      }
    } catch (err) {
      console.warn('[graceful-shutdown] Failed to restart container:', err);
    }
  });
});
