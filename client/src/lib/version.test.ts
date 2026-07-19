import { describe, it, expect } from 'vitest';
import { isOutdated, isReleaseVersion, buildNewIssueUrl, canReportIssue } from './version';

describe('isOutdated', () => {
  it('flags a lower semver as outdated', () => {
    expect(isOutdated('2.3.4', '2.3.5')).toBe(true);
    expect(isOutdated('2.3.4', '2.4.0')).toBe(true);
    expect(isOutdated('1.9.9', '2.0.0')).toBe(true);
  });
  it('treats equal or newer as up-to-date', () => {
    expect(isOutdated('2.3.5', '2.3.5')).toBe(false);
    expect(isOutdated('2.3.6', '2.3.5')).toBe(false);
    expect(isOutdated('3.0.0', '2.9.9')).toBe(false);
  });
  it('tolerates missing patch segments', () => {
    expect(isOutdated('2.3', '2.3.1')).toBe(true);
    expect(isOutdated('2.3', '2.3.0')).toBe(false);
  });
});

describe('isReleaseVersion', () => {
  it('excludes dev and staging builds', () => {
    expect(isReleaseVersion('dev')).toBe(false);
    expect(isReleaseVersion('staging-abc123')).toBe(false);
    expect(isReleaseVersion('2.3.5')).toBe(true);
  });
});

describe('buildNewIssueUrl', () => {
  it('URL-encodes the title and body into the template tokens', () => {
    const tmpl = 'https://github.com/o/r/issues/new?title={title}&body={body}';
    const url = buildNewIssueUrl(tmpl, '', '**Version:** v2.3.5\nbrowser & os');
    expect(url).toBe(
      'https://github.com/o/r/issues/new?title=&body=**Version%3A**%20v2.3.5%0Abrowser%20%26%20os',
    );
  });
  it('works with the GitLab template param names', () => {
    const tmpl = 'https://gitlab.com/o/r/-/issues/new?issue[title]={title}&issue[description]={body}';
    expect(buildNewIssueUrl(tmpl, '', 'x')).toBe(
      'https://gitlab.com/o/r/-/issues/new?issue[title]=&issue[description]=x',
    );
  });
});

describe('canReportIssue', () => {
  const base = { hasTemplate: true, loading: false, outdated: false, acknowledged: false };
  it('allows reporting when up to date', () => {
    expect(canReportIssue(base)).toBe(true);
  });
  it('blocks reporting when outdated and not acknowledged', () => {
    expect(canReportIssue({ ...base, outdated: true })).toBe(false);
  });
  it('allows reporting when outdated but acknowledged', () => {
    expect(canReportIssue({ ...base, outdated: true, acknowledged: true })).toBe(true);
  });
  it('blocks while loading or without a template', () => {
    expect(canReportIssue({ ...base, loading: true })).toBe(false);
    expect(canReportIssue({ ...base, hasTemplate: false })).toBe(false);
  });
});
