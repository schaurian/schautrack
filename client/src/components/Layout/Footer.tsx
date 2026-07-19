import { useTranslation } from 'react-i18next';
import { useVersionInfo } from '@/hooks/useVersionInfo';

export default function Footer() {
  const { t } = useTranslation('common');
  const { current, outdated, repoUrl } = useVersionInfo();

  const displayVersion = current
    ? (current.startsWith('staging') || current === 'dev' ? current : `v${current}`)
    : null;
  const githubHref = repoUrl ?? 'https://github.com/schaurian/schautrack';

  return (
    <footer className="mt-auto px-4 py-4">
      <div className="mx-auto flex max-w-[1100px] flex-col items-center gap-2">
        <div className="text-sm font-semibold text-foreground">
          {t('footer.tagline')}
        </div>
        <div className="flex flex-wrap items-center justify-center gap-3 text-sm">
          <a href="/imprint" className="text-muted-foreground transition-colors hover:text-foreground">{t('footer.imprint')}</a>
          <span className="text-muted-foreground/30">·</span>
          <a href="/privacy" className="text-muted-foreground transition-colors hover:text-foreground">{t('footer.privacy')}</a>
          <span className="text-muted-foreground/30">·</span>
          <a href="/terms" className="text-muted-foreground transition-colors hover:text-foreground">{t('footer.terms')}</a>
          <span className="text-muted-foreground/30">·</span>
          <a
            href="https://play.google.com/store/apps/details?id=to.schauer.schautrack"
            target="_blank"
            rel="noopener noreferrer"
            title={t('footer.androidApp')}
            className="text-muted-foreground/50 transition-colors hover:text-foreground"
          >
            <svg width="16" height="16" viewBox="-9 0 274 274">
              <path d="M188.81319,178.874645 C221.272218,161.051727 245.880297,147.470853 248.001319,146.415618 C254.78648,142.806714 261.79324,133.256838 248.001319,125.838536 C243.548228,123.506467 219.573289,110.347687 188.81319,93.3795092 L146.171146,136.443648 L188.81319,178.874645 Z" fill="#FFD900"/>
              <path d="M146.171146,136.443648 L10.3940643,273.286517 C13.5808739,273.708611 17.1792251,272.864423 21.4212696,270.532353 C30.3274526,265.657168 124.739324,214.098388 188.81319,178.885198 L146.171146,136.443648 Z" fill="#F43249"/>
              <path d="M146.171146,136.443648 L188.81319,93.5905562 C188.81319,93.5905562 30.9711459,7.45172685 21.4212696,2.36549437 C17.8229184,0.233919759 13.7919209,-0.399221214 10.1830173,0.233919759 L146.171146,136.443648 Z" fill="#00EE76"/>
              <path d="M146.171146,136.443648 L10.1830173,0.233919759 C4.6641385,1.51075405 0,6.38593954 0,16.3579099 C0,32.270853 0,244.003747 0,257.162527 C0,266.290309 3.60890354,272.864423 10.3940643,273.497564 L146.171146,136.443648 Z" fill="#00D3FF"/>
            </svg>
          </a>
          <a
            href={githubHref}
            target="_blank"
            rel="noopener noreferrer"
            className="text-muted-foreground/50 transition-colors hover:text-foreground"
            title={outdated ? t('footer.updateAvailable') : t('footer.viewOnGithub')}
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z" />
            </svg>
          </a>
          {displayVersion && (
            <span className={`text-xs ${outdated ? 'text-destructive' : 'text-muted-foreground/30'}`}>
              {displayVersion}
            </span>
          )}
        </div>
      </div>
    </footer>
  );
}
