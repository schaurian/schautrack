import { useEffect, useState } from 'react';
import { isOutdated, isReleaseVersion, type LatestVersionInfo } from '@/lib/version';

export interface VersionInfo {
  /** Running build version (from /api/health), e.g. "2.3.5", "dev", "staging-abc". */
  current: string | null;
  /** Newest released version, or null when undeterminable (check disabled/unreachable). */
  latest: string | null;
  /** True only when we positively know current < latest for a real release build. */
  outdated: boolean;
  provider: string | null;
  repoUrl: string | null;
  issuesUrl: string | null;
  newIssueUrlTemplate: string | null;
  loading: boolean;
}

const initial: VersionInfo = {
  current: null,
  latest: null,
  outdated: false,
  provider: null,
  repoUrl: null,
  issuesUrl: null,
  newIssueUrlTemplate: null,
  loading: true,
};

/** Fetches the running version and the configured release/issue source, and
 *  derives whether the instance is outdated. Shared by the footer and the
 *  Settings "Report an Issue" card. Degrades gracefully: if the latest version
 *  can't be determined, `outdated` stays false. */
export function useVersionInfo(): VersionInfo {
  const [info, setInfo] = useState<VersionInfo>(initial);

  useEffect(() => {
    let cancelled = false;

    (async () => {
      let current: string | null = null;
      try {
        const health = await fetch('/api/health').then((r) => r.json());
        current = health?.version ?? null;
      } catch {
        // Health unreachable — leave current null; the card/footer just hide the version.
      }

      let rel: Partial<LatestVersionInfo> = {};
      try {
        rel = await fetch('/api/latest-version').then((r) => r.json());
      } catch {
        // Release source unreachable — URLs fall back to null, outdated stays false.
      }

      if (cancelled) return;

      const latest = rel.latest ?? null;
      const outdated =
        !!current && !!latest && isReleaseVersion(current) && isOutdated(current, latest);

      setInfo({
        current,
        latest,
        outdated,
        provider: rel.provider ?? null,
        repoUrl: rel.repoUrl ?? null,
        issuesUrl: rel.issuesUrl ?? null,
        newIssueUrlTemplate: rel.newIssueUrlTemplate ?? null,
        loading: false,
      });
    })();

    return () => {
      cancelled = true;
    };
  }, []);

  return info;
}
