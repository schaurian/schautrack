import { Link } from 'react-router';
import { Button } from '@/components/ui/Button';

const FEATURES = [
  {
    icon: (
      <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 2v20M2 12h20" />
      </svg>
    ),
    title: 'Simple Logging',
    desc: 'Log calories and macros in seconds. No barcode scanning, no food databases to search through.',
  },
  {
    icon: (
      <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <rect x="3" y="3" width="18" height="18" rx="2" />
        <path d="M3 9h18M9 21V9" />
      </svg>
    ),
    title: 'AI Estimation',
    desc: 'Snap a photo and let AI estimate calories and macros for you.',
  },
  {
    icon: (
      <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
        <circle cx="9" cy="7" r="4" />
        <path d="M23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75" />
      </svg>
    ),
    title: 'Share with Friends',
    desc: 'Link accounts with friends or partners to keep each other accountable.',
  },
  {
    icon: (
      <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      </svg>
    ),
    title: 'Self-Hostable',
    desc: 'Run your own instance. Your data stays yours.',
  },
];

export default function Landing() {
  return (
    <div className="pt-20 pb-4 max-md:pt-10">
      <section className="mx-auto mb-20 max-w-[700px] text-center max-md:mb-12">
        <h1 className="mb-6 text-[clamp(2rem,6vw,3.5rem)] font-bold leading-[1.1] tracking-tight bg-gradient-to-br from-foreground to-primary bg-clip-text text-transparent">
          Track nutrition, not complexity
        </h1>
        <p className="mb-10 text-xl leading-relaxed text-muted-foreground max-w-2xl mx-auto max-md:text-lg">
          A free, open-source, self-hostable nutrition tracker that stays out of your way. Log calories and macros, set goals, and see how your day is going at a glance. Your data, your server.
        </p>
        <div className="flex justify-center gap-4 flex-wrap">
          <Link to="/register"><Button size="lg" className="px-8 py-3 text-base">Get Started</Button></Link>
          <a href="https://github.com/schaurian/schautrack" target="_blank" rel="noopener">
            <Button variant="outline" size="lg" className="px-8 py-3 text-base">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" className="mr-2">
                <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z" />
              </svg>
              View Source
            </Button>
          </a>
        </div>
      </section>

      <section className="grid grid-cols-1 gap-6 sm:grid-cols-2 mb-20 max-md:mb-12">
        {FEATURES.map((f) => (
          <div key={f.title} className="rounded-xl border border-border bg-card p-6 text-left">
            <div className="mb-4 size-14 rounded-xl bg-gradient-to-br from-primary/15 to-secondary/15 grid place-items-center text-foreground">
              {f.icon}
            </div>
            <h3 className="mb-2 text-lg font-semibold text-foreground">{f.title}</h3>
            <p className="text-[0.95rem] leading-relaxed text-muted-foreground">{f.desc}</p>
          </div>
        ))}
      </section>

      <section className="text-center">
        <a href="https://github.com/schaurian/schautrack#android-app" target="_blank" rel="noopener">
          <img src="/google-play-badge.png" alt="Get it on Google Play" className="h-14 mx-auto" />
        </a>
      </section>
    </div>
  );
}
