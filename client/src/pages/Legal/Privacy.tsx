import { Card } from '@/components/ui/Card';

export default function Privacy() {
  return (
    <div className="mx-auto max-w-2xl py-12">
      <Card>
        <h1 className="mb-6 text-2xl font-semibold">Privacy Policy</h1>
        <div className="space-y-6 text-sm leading-relaxed text-muted-foreground">
          <p>Schautrack collects only the data necessary to provide the calorie and macro tracking service.</p>
          <h3 className="font-semibold text-foreground">Data We Collect</h3>
          <ul className="list-disc pl-6">
            <li>Email address (for authentication)</li>
            <li>Calorie and macro entries you create</li>
            <li>Weight entries you create</li>
            <li>Timezone and display preferences</li>
          </ul>
          <h3 className="font-semibold text-foreground">Third-Party Services</h3>
          <ul className="list-disc pl-6">
            <li>
              Barcode scanning uses{' '}
              <a href="https://world.openfoodfacts.org" target="_blank" rel="noopener noreferrer" className="text-primary underline">Open Food Facts</a>
              , a free and open food products database licensed under the{' '}
              <a href="https://opendatacommons.org/licenses/odbl/1-0/" target="_blank" rel="noopener noreferrer" className="text-primary underline">Open Database License (ODbL)</a>.
              When you scan a barcode, the barcode number is sent to Open Food Facts to retrieve product nutrition data.
            </li>
          </ul>
          <h3 className="font-semibold text-foreground">Data We Don't Collect</h3>
          <ul className="list-disc pl-6">
            <li>No analytics or tracking scripts</li>
            <li>No third-party cookies</li>
            <li>No data sold to third parties</li>
          </ul>
          <h3 className="font-semibold text-foreground">Data Deletion</h3>
          <p>You can delete your account and all associated data at any time from Settings.</p>
        </div>
      </Card>
    </div>
  );
}
