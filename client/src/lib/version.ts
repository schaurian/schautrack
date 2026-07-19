// Shared version/update-check helpers, consumed by the footer and the Settings
// "Report an Issue" card via the useVersionInfo hook.

/** Shape of GET /api/latest-version. `latest` is null when the update check is
 *  disabled or the provider is unreachable; the URL fields are static config and
 *  are always present. */
export interface LatestVersionInfo {
  latest: string | null;
  provider: string;
  repoUrl: string;
  issuesUrl: string;
  newIssueUrlTemplate: string;
}

/** True when `current` is a lower semver (major.minor.patch) than `latest`. */
export function isOutdated(current: string, latest: string): boolean {
  const c = current.split('.').map(Number);
  const l = latest.split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    if ((c[i] || 0) < (l[i] || 0)) return true;
    if ((c[i] || 0) > (l[i] || 0)) return false;
  }
  return false;
}

/** Non-release builds ('dev', 'staging*') are never compared against upstream. */
export function isReleaseVersion(version: string): boolean {
  return version !== 'dev' && !version.startsWith('staging');
}

/** Substitute a provider new-issue URL template's {title}/{body} tokens with
 *  URL-encoded values. */
export function buildNewIssueUrl(template: string, title: string, body: string): string {
  return template
    .replace('{title}', encodeURIComponent(title))
    .replace('{body}', encodeURIComponent(body));
}

/** Soft gate for the "Report an Issue" action. An outdated instance must tick the
 *  acknowledgement checkbox before reporting; up-to-date (or undeterminable)
 *  instances report directly. Requires a known new-issue template and a finished
 *  load. */
export function canReportIssue(opts: {
  hasTemplate: boolean;
  loading: boolean;
  outdated: boolean;
  acknowledged: boolean;
}): boolean {
  if (!opts.hasTemplate || opts.loading) return false;
  if (opts.outdated && !opts.acknowledged) return false;
  return true;
}
