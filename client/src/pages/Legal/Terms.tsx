import { Card } from '@/components/ui/Card';

export default function Terms() {
  return (
    <div className="mx-auto max-w-2xl py-12">
      <Card>
        <h1 className="mb-6 text-2xl font-semibold">Terms of Service</h1>
        <div className="space-y-6 text-sm leading-relaxed text-muted-foreground">
          <p>By using Schautrack, you agree to these terms.</p>

          <h3 className="font-semibold text-foreground">Service</h3>
          <p>Schautrack provides calorie and nutrition tracking tools. The service is provided "as is" without warranty.</p>

          <h3 className="font-semibold text-foreground">Not Medical Advice</h3>
          <p>
            Calorie counts, macro estimates from photos, and barcode nutrition data are informational only and may be
            inaccurate. Schautrack is not a medical device and is not a substitute for professional medical, dietary, or
            nutritional advice. Do not rely on it for clinical decisions or for the management of any medical condition.
            Verify nutrition information on product packaging when precision matters, and consult a qualified professional
            for medical or dietary concerns.
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
          <p>Don't abuse the service, attempt to access other users' data, or use automated tools to scrape the service.</p>

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
