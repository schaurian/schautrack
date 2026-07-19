import { Card } from '@/components/ui/Card';

export default function Terms() {
  return (
    <div className="mx-auto max-w-2xl py-12">
      <Card>
        <h1 className="mb-2 text-2xl font-semibold">Terms of Service</h1>
        <p className="mb-6 text-xs text-muted-foreground">Last updated: 19 July 2026</p>
        <div className="space-y-6 text-sm leading-relaxed text-muted-foreground">
          <p>By using Schautrack, you agree to these terms.</p>

          <h3 className="font-semibold text-foreground">Service</h3>
          <p>
            Schautrack provides calorie, nutrition, and weight tracking tools, including an optional weight planner that
            estimates a daily calorie budget and timeline from the information you provide. The service is offered free
            of charge.
          </p>

          <h3 className="font-semibold text-foreground">Eligibility</h3>
          <p>
            You must be at least 16 years old to use Schautrack. This threshold follows from the age of digital consent
            applicable to the health-data consent the service relies on (Art.&nbsp;8 GDPR as implemented in Germany).
          </p>

          <h3 className="font-semibold text-foreground">Not Medical Advice</h3>
          <p>
            Calorie counts, macro estimates from photos, barcode nutrition data, and the weight planner&apos;s
            calculations &mdash; including calorie budgets, BMI values, and projected timelines &mdash; are formula-based
            estimates and informational only. They may be inaccurate. Schautrack is not a medical device and is not a
            substitute for professional medical, dietary, or nutritional advice. It is not suitable for managing eating
            disorders or any medical condition. Consult a qualified professional before starting a weight-loss or
            weight-gain program, and verify nutrition information on product packaging when precision matters.
          </p>

          <h3 className="font-semibold text-foreground">Your Account</h3>
          <p>
            You are responsible for maintaining the security of your account and for any credentials you choose to set up,
            including your password, two-factor authentication codes, backup codes, and passkeys.
          </p>

          <h3 className="font-semibold text-foreground">Account Linking</h3>
          <p>
            If you accept a link request from another user, that user can read your calorie, macro, weight, note and todo
            entries. Only link accounts with people you trust, and remove the link from Settings if you no longer want to
            share.
          </p>

          <h3 className="font-semibold text-foreground">Third-Party Data</h3>
          <p>
            Barcode nutrition data is provided by{' '}
            <a href="https://world.openfoodfacts.org" target="_blank" rel="noopener noreferrer" className="text-primary underline">Open Food Facts</a>
            {' '}under the{' '}
            <a href="https://opendatacommons.org/licenses/odbl/1-0/" target="_blank" rel="noopener noreferrer" className="text-primary underline">Open Database License (ODbL)</a>.
            This data is community-contributed and may not always be accurate.
          </p>

          <h3 className="font-semibold text-foreground">Acceptable Use</h3>
          <p>Don&apos;t abuse the service, attempt to access other users&apos; data, or use automated tools to scrape the service.</p>

          <h3 className="font-semibold text-foreground">Availability</h3>
          <p>
            Schautrack is provided free of charge and without an availability guarantee. We may modify or discontinue the
            service; if we discontinue it, we will give reasonable advance notice by email so you can export your data
            from Settings.
          </p>

          <h3 className="font-semibold text-foreground">Termination</h3>
          <p>
            You can stop using Schautrack and delete your account, including all associated data, at any time from
            Settings. We may suspend or terminate accounts that violate these terms or abuse the service; where
            reasonable, we will notify you by email beforehand and give you the opportunity to export your data.
          </p>

          <h3 className="font-semibold text-foreground">Liability</h3>
          <p>
            We are liable without limitation for damages caused by intent or gross negligence, for injury to life, body,
            or health, and under the German Product Liability Act. For slight negligence, we are liable only for breaches
            of essential contractual obligations (obligations whose fulfilment makes the proper performance of the
            contract possible in the first place and on whose fulfilment you may regularly rely), limited to the damage
            that is typical for this kind of contract and foreseeable at its conclusion. Any further liability is
            excluded. This does not shift the burden of proof to your disadvantage.
          </p>

          <h3 className="font-semibold text-foreground">Changes to These Terms</h3>
          <p>
            These terms may be updated from time to time. The version published on this page is the version that applies
            to your use of the service. Material changes will be communicated by email to your registered address where
            reasonably possible.
          </p>

          <h3 className="font-semibold text-foreground">Governing Law</h3>
          <p>
            These terms are governed by the laws of the Federal Republic of Germany. Mandatory consumer protection rights
            of your country of residence remain unaffected.
          </p>
        </div>
      </Card>
    </div>
  );
}
