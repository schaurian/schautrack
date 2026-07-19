import { Card } from '@/components/ui/Card';

export default function Imprint() {
  return (
    <div className="mx-auto max-w-2xl py-12">
      <Card>
        <h1 className="mb-6 text-2xl font-semibold">Imprint</h1>
        <div className="space-y-6 text-sm leading-relaxed text-muted-foreground">
          <div className="space-y-4">
            <h3 className="font-semibold text-foreground">Information pursuant to &sect;&nbsp;5 DDG</h3>
            {/* Address and email are rendered as server-generated SVGs as a
                deliberate protection against address/email harvesting bots. */}
            <img src="/imprint/address.svg" alt="Postal address of the operator" className="max-w-full" />
            <img src="/imprint/email.svg" alt="Email address of the operator" className="max-w-full" />
          </div>

          <div className="space-y-4">
            <h3 className="font-semibold text-foreground">Responsible for content pursuant to &sect;&nbsp;18&nbsp;(2) MStV</h3>
            <img src="/imprint/address.svg" alt="Name and postal address of the person responsible for content" className="max-w-full" />
          </div>

          <div className="space-y-2">
            <h3 className="font-semibold text-foreground">Consumer Dispute Resolution</h3>
            <p>
              We are neither willing nor obliged to participate in dispute resolution proceedings before a consumer
              arbitration board (&sect;&nbsp;36 VSBG).
            </p>
          </div>
        </div>
      </Card>
    </div>
  );
}
