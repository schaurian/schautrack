import { useState, useEffect } from 'react';

function isOutdated(current: string, latest: string): boolean {
  const c = current.split('.').map(Number);
  const l = latest.split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    if ((c[i] || 0) < (l[i] || 0)) return true;
    if ((c[i] || 0) > (l[i] || 0)) return false;
  }
  return false;
}

export default function Footer() {
  const [version, setVersion] = useState<string | null>(null);
  const [outdated, setOutdated] = useState(false);

  useEffect(() => {
    fetch('/api/health')
      .then((r) => r.json())
      .then((d) => {
        if (d.version && d.version !== 'dev') {
          setVersion(d.version);
          // Check for updates (cached in localStorage, 1 hour TTL)
          if (!d.version.startsWith('staging')) {
            const cacheKey = 'schautrack_latest_version';
            const cached = localStorage.getItem(cacheKey);
            if (cached) {
              try {
                const { v, t } = JSON.parse(cached);
                if (Date.now() - t < 3600000 && v) {
                  if (isOutdated(d.version, v)) setOutdated(true);
                  return;
                }
              } catch {}
            }
            fetch('https://api.github.com/repos/schaurian/schautrack/releases/latest')
              .then((r) => r.json())
              .then((rel) => {
                const latest = rel.tag_name?.replace(/^v/, '');
                if (latest) {
                  localStorage.setItem(cacheKey, JSON.stringify({ v: latest, t: Date.now() }));
                  if (isOutdated(d.version, latest)) setOutdated(true);
                }
              })
              .catch(() => {});
          }
        }
      })
      .catch(() => {});
  }, []);

  const displayVersion = version
    ? (version.startsWith('staging') ? version : `v${version}`)
    : null;

  return (
    <footer className="mt-auto px-4 py-6 text-center text-xs text-muted-foreground">
      <p className="mb-2 italic opacity-70">You got this. Trust me.</p>
      <div className="flex justify-center items-center gap-2">
        <a href="/imprint" className="text-muted-foreground transition-colors hover:text-foreground">Imprint</a>
        <span className="text-muted-foreground/40">&mdash;</span>
        <a href="/privacy" className="text-muted-foreground transition-colors hover:text-foreground">Privacy</a>
        <span className="text-muted-foreground/40">&mdash;</span>
        <a href="/terms" className="text-muted-foreground transition-colors hover:text-foreground">Terms</a>
        <a
          href="https://github.com/schaurian/schautrack"
          target="_blank"
          rel="noopener noreferrer"
          className="text-muted-foreground/50 transition-colors hover:text-foreground ml-1"
          title="View on GitHub"
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor" className="align-middle">
            <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z" />
          </svg>
        </a>
      </div>
      {displayVersion && (
        <div className="mt-2">
          <a
            href="https://github.com/schaurian/schautrack"
            target="_blank"
            rel="noopener noreferrer"
            className={`transition-colors hover:text-foreground ${outdated ? 'text-destructive' : 'text-muted-foreground/50'}`}
            title={outdated ? 'Update available — click to view' : undefined}
          >
            {displayVersion}
          </a>
        </div>
      )}
    </footer>
  );
}
