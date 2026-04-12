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
          <h3 className="font-semibold text-foreground">Your Account</h3>
          <p>You are responsible for maintaining the security of your account and password.</p>
          <h3 className="font-semibold text-foreground">Third-Party Data</h3>
          <p>
            Barcode nutrition data is provided by{' '}
            <a href="https://world.openfoodfacts.org" target="_blank" rel="noopener noreferrer" className="text-primary underline">Open Food Facts</a>
            {' '}under the{' '}
            <a href="https://opendatacommons.org/licenses/odbl/1-0/" target="_blank" rel="noopener noreferrer" className="text-primary underline">Open Database License (ODbL)</a>.
            This data is community-contributed and may not always be accurate. Verify nutrition information on product packaging when precision matters.
          </p>
          <h3 className="font-semibold text-foreground">Acceptable Use</h3>
          <p>Don't abuse the service, attempt to access other users' data, or use automated tools to scrape the service.</p>
        </div>
      </Card>
    </div>
  );
}
