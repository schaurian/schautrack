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
            <li>Email address (for authentication and account recovery)</li>
            <li>Calorie, macro, and weight entries you create</li>
            <li>Daily notes and todos (if you enable them)</li>
            <li>Timezone and display preferences</li>
            <li>Authentication material you choose to set up: password hash, TOTP secret, backup codes, passkey credentials</li>
          </ul>

          <h3 className="font-semibold text-foreground">Cookies</h3>
          <p>
            Schautrack sets one strictly necessary first-party session cookie (<code>schautrack.sid</code>) to keep you signed in.
            No analytics or third-party cookies are used.
          </p>

          <h3 className="font-semibold text-foreground">Logs &amp; Security</h3>
          <p>
            For sensitive account actions (logins, password and email changes, 2FA changes, passkey changes, account deletion)
            we record the action, your IP address, and your user agent so the account owner can review activity and so we can
            detect abuse. The same information is held briefly to rate-limit authentication endpoints.
          </p>

          <h3 className="font-semibold text-foreground">Account Linking</h3>
          <p>
            If you accept a link request from another user, that user can read your calorie, macro, weight, note and todo
            entries. They cannot edit or delete them. You can remove the link at any time from Settings.
          </p>

          <h3 className="font-semibold text-foreground">Sub-processors</h3>
          <p>We use a small number of external services to operate Schautrack:</p>
          <ul className="list-disc pl-6">
            <li>
              <strong>AI nutrition estimation:</strong> When you submit a food photo for estimation, the photo is sent to the
              AI provider configured by the operator of this Schautrack instance &mdash; currently either OpenAI or Anthropic Claude
              (both based in the United States), or a self-hosted Ollama instance. You can also configure your own API key
              for any of these providers in Settings. If you do not use this feature, no photo data is shared with any AI
              provider.
            </li>
            <li>
              <strong>Barcode lookups:</strong> Scanned barcode numbers are sent to{' '}
              <a href="https://world.openfoodfacts.org" target="_blank" rel="noopener noreferrer" className="text-primary underline">Open Food Facts</a>
              {' '}to retrieve product nutrition data, under the{' '}
              <a href="https://opendatacommons.org/licenses/odbl/1-0/" target="_blank" rel="noopener noreferrer" className="text-primary underline">Open Database License (ODbL)</a>.
            </li>
            <li><strong>Hosting:</strong> an EU-based hosting provider in Germany.</li>
            <li><strong>Email delivery:</strong> a transactional email provider for verification, password reset, and account-change notifications.</li>
            <li><strong>Backups:</strong> encrypted offsite backups stored in the EU.</li>
          </ul>
          <h3 className="font-semibold text-foreground">International Transfers</h3>
          <p>
            If the configured AI provider is OpenAI or Anthropic Claude, submitting a photo for estimation transfers that
            image to a recipient in the United States. Such transfers rely on the provider's Standard Contractual Clauses.
            You can avoid these transfers by not using the AI estimation feature, or by configuring a self-hosted Ollama
            endpoint in Settings.
          </p>

          <h3 className="font-semibold text-foreground">Retention</h3>
          <ul className="list-disc pl-6">
            <li>Calorie, macro, weight, note, and todo entries are retained until you delete them or delete your account.</li>
            <li>Authenticated sessions expire 30 days after your last visit; anonymous sessions expire after 15 minutes of inactivity.</li>
            <li>Audit log entries (sensitive auth actions, with IP and user agent) are retained for the lifetime of the account.</li>
            <li>When you delete your account, all associated data is removed.</li>
          </ul>

          <h3 className="font-semibold text-foreground">Data We Don't Collect</h3>
          <ul className="list-disc pl-6">
            <li>No analytics or tracking scripts</li>
            <li>No third-party cookies</li>
            <li>No data sold to third parties</li>
          </ul>

          <h3 className="font-semibold text-foreground">Your Rights &amp; Data Deletion</h3>
          <p>
            You can delete your account and all associated data at any time from Settings. For other GDPR requests (access,
            rectification, portability, objection), contact the address listed on the{' '}
            <a href="/imprint" className="text-primary underline">Imprint</a> page.
          </p>
          <p>
            If you reside in the EU/EEA, you also have the right to lodge a complaint with your local data-protection
            supervisory authority. The competent authority for the operator of this instance is the{' '}
            <a href="https://www.lda.bayern.de/" target="_blank" rel="noopener noreferrer" className="text-primary underline">
              Bayerisches Landesamt f&uuml;r Datenschutzaufsicht (BayLDA)
            </a>.
          </p>
        </div>
      </Card>
    </div>
  );
}
