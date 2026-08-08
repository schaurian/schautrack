import { test, expect } from '@playwright/test';
import { execFileSync } from 'child_process';

// Infrastructure test: verifies the Go server handles SIGTERM gracefully (exit code 0).
//
// It does NOT signal the web container the rest of the suite is talking to.
// Doing that made this test a global side effect — the app was down for the
// length of the drain plus a restart — which in turn forced it to run last,
// which in turn forced `dependencies: ['chromium', 'invite']` in
// playwright.config.ts. That dependency couples ordering to SUCCESS: one
// exhausted retry anywhere in the 212-test `chromium` project and this test is
// never dispatched, reported only as "did not run". Losing graceful-shutdown
// coverage to an unrelated flake is exactly the silent-green failure mode this
// repo has been eliminating.
//
// Instead we clone the running web container — same image, same env, same
// network, no published ports — signal the clone, and assert on ITS exit code.
// The property under test (the Go server drains and exits 0 on SIGTERM) belongs
// to the binary, not to the shared stack, so the clone tests it just as well
// while having no effect on anything else. The `shutdown` project therefore
// needs no dependencies at all and can run concurrently with everything.
//
// E2E_WEB_CONTAINER names the container to clone. It defaults to the container
// `compose.test.yml` produces under its own project name, which is what CI and
// `npm run test:e2e` use; override it when driving a second, differently-named
// stack.
const WEB_CONTAINER = process.env.E2E_WEB_CONTAINER || 'schautrack-test-web-1';
const PROBE_CONTAINER = `${WEB_CONTAINER}-sigterm-probe`;

function docker(args: string[], timeoutMs = 15000): string {
  return execFileSync('docker', args, { encoding: 'utf-8', timeout: timeoutMs })
    .trim()
    .replace(/^"|"$/g, '');
}

function inspect(container: string, format: string): string {
  return docker(['inspect', container, '--format', format]);
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

test.describe('Graceful Shutdown', () => {
  // Cloning, booting, draining (the server allows itself 30s) and cleaning up
  // does not fit the 60s default.
  test.setTimeout(180_000);

  test('SIGTERM exits cleanly with exit code 0', async () => {
    let status = '';
    let image = '';
    let network = '';
    let env: string[] = [];

    // No test.skip() inside the try: it signals by throwing, which the catch
    // would swallow and report as the wrong reason.
    try {
      status = inspect(WEB_CONTAINER, '{{.State.Status}}');
      image = inspect(WEB_CONTAINER, '{{.Config.Image}}');
      // A compose service is on exactly one network here; take the first.
      network = inspect(WEB_CONTAINER, '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{"\\n"}}{{end}}')
        .split('\n')
        .map((n) => n.trim())
        .filter(Boolean)[0];
      env = inspect(WEB_CONTAINER, '{{range .Config.Env}}{{println .}}{{end}}')
        .split('\n')
        .map((e) => e.trim())
        .filter(Boolean);
    } catch {
      status = 'absent';
    }

    if (status !== 'running') {
      test.skip(true, `Container ${WEB_CONTAINER} is ${status || 'absent'} — skipping graceful shutdown test`);
      return;
    }

    expect(image, 'could not read the web image name').toBeTruthy();
    expect(network, 'could not read the web container network').toBeTruthy();

    // A stale probe from an aborted run would make `docker run --name` fail.
    try {
      docker(['rm', '-f', PROBE_CONTAINER]);
    } catch {
      // Nothing to remove — the normal case.
    }

    try {
      // No published ports: the clone listens on :3000 inside its own network
      // namespace, so it cannot collide with the real web container. Env is
      // passed as separate argv entries (execFileSync, no shell) rather than
      // through --env-file, so values are never re-parsed or re-quoted.
      docker(
        ['run', '-d', '--name', PROBE_CONTAINER, '--network', network, ...env.flatMap((e) => ['-e', e]), image],
        60_000
      );

      // Wait until the clone actually serves traffic. Signalling a process that
      // has not finished booting would test the wrong thing — and this request
      // is also what makes the drain path meaningful rather than a no-op on an
      // idle listener.
      let ready = false;
      for (let i = 0; i < 60; i++) {
        await sleep(500);
        try {
          docker(['exec', PROBE_CONTAINER, 'wget', '-q', '--spider', 'http://localhost:3000/api/health'], 5000);
          ready = true;
          break;
        } catch {
          // Still starting, or already dead — the assertion below reports which.
        }
      }
      if (!ready) {
        let logs = '';
        try {
          logs = docker(['logs', '--tail', '50', PROBE_CONTAINER]);
        } catch {
          logs = '(no logs)';
        }
        expect(ready, `probe container never became healthy. Logs:\n${logs}`).toBe(true);
      }

      docker(['kill', '--signal=SIGTERM', PROBE_CONTAINER]);

      // Up to 45s: the server's own drain deadline is 30s.
      let exited = false;
      for (let i = 0; i < 90; i++) {
        await sleep(500);
        if (inspect(PROBE_CONTAINER, '{{.State.Status}}') === 'exited') {
          exited = true;
          break;
        }
      }
      expect(exited, 'server did not exit within 45s of SIGTERM').toBe(true);

      expect(inspect(PROBE_CONTAINER, '{{.State.ExitCode}}')).toBe('0');
    } finally {
      try {
        docker(['rm', '-f', PROBE_CONTAINER]);
      } catch {
        // Best effort — a leaked probe is removed by the next run's pre-clean.
      }
    }
  });
});
