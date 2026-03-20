import { Link } from 'react-router';
import { Button } from '@/components/ui/Button';

const FEATURES = [
  {
    icon: (
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className="text-macro-kcal">
        <path d="M12 20V10" /><path d="M18 20V4" /><path d="M6 20v-4" />
      </svg>
    ),
    title: 'Simple Tracking',
    desc: 'Log calories and macros in seconds. Supports math expressions like 200+150.',
    color: 'border-l-macro-kcal',
  },
  {
    icon: (
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className="text-macro-carbs">
        <path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z" />
        <circle cx="12" cy="13" r="4" />
      </svg>
    ),
    title: 'AI Estimation',
    desc: 'Snap a photo of your food and let AI estimate the calories and macros.',
    color: 'border-l-macro-carbs',
  },
  {
    icon: (
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className="text-macro-fiber">
        <path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" /><circle cx="9" cy="7" r="4" />
        <path d="M22 21v-2a4 4 0 0 0-3-3.87" /><path d="M16 3.13a4 4 0 0 1 0 7.75" />
      </svg>
    ),
    title: 'Share Progress',
    desc: 'Link accounts with friends and see each other\'s daily progress in real-time.',
    color: 'border-l-macro-fiber',
  },
  {
    icon: (
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className="text-macro-fat">
        <rect width="20" height="8" x="2" y="2" rx="2" ry="2" /><rect width="20" height="8" x="2" y="14" rx="2" ry="2" />
        <line x1="6" x2="6.01" y1="6" y2="6" /><line x1="6" x2="6.01" y1="18" y2="18" />
      </svg>
    ),
    title: 'Self-Hostable',
    desc: 'Run your own instance with Docker. Your data stays on your infrastructure.',
    color: 'border-l-macro-fat',
  },
];

export default function Landing() {
  return (
    <div className="py-16 max-md:py-8">
      <section className="mx-auto mb-16 max-w-lg text-center max-md:mb-10">
        <div className="mb-6 inline-flex items-center gap-2 rounded-full border border-border bg-card px-4 py-1.5 text-xs text-muted-foreground">
          <span className="size-1.5 rounded-full bg-success animate-pulse" />
          Open source &middot; Self-hostable
        </div>
        <h1 className="mb-5 text-4xl font-bold leading-[1.1] tracking-tight text-foreground max-md:text-3xl">
          Track your nutrition,<br />
          <span className="bg-gradient-to-r from-primary to-secondary bg-clip-text text-transparent">your way.</span>
        </h1>
        <p className="mb-8 text-base leading-relaxed text-muted-foreground max-w-md mx-auto">
          Simple calorie and macro tracking with AI-powered food estimation. Privacy-first, no ads, no subscriptions.
        </p>
        <div className="flex justify-center gap-3">
          <Link to="/register"><Button size="lg">Get Started</Button></Link>
          <Link to="/login"><Button variant="outline" size="lg">Log In</Button></Link>
        </div>
      </section>

      <section className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        {FEATURES.map((f) => (
          <div key={f.title} className={`rounded-md border border-border border-l-3 ${f.color} bg-card p-5`}>
            <div className="mb-3">{f.icon}</div>
            <h3 className="mb-1.5 text-sm font-semibold text-foreground">{f.title}</h3>
            <p className="text-sm leading-relaxed text-muted-foreground">{f.desc}</p>
          </div>
        ))}
      </section>

      <section className="mt-16 text-center max-md:mt-10">
        <p className="text-xs text-muted-foreground">
          Built with React, Go, and PostgreSQL.{' '}
          <a href="https://github.com/schaurian/schautrack" className="hover:underline" target="_blank" rel="noopener">View on GitHub</a>
        </p>
      </section>
    </div>
  );
}
