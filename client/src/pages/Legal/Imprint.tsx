import { Card } from '@/components/ui/Card';

export default function Imprint() {
  return (
    <div className="mx-auto max-w-2xl py-12">
      <Card>
        <h1 className="mb-6 text-2xl font-semibold">Imprint</h1>
        <div className="space-y-4 text-sm leading-relaxed text-muted-foreground">
          <img src="/imprint/address.svg" alt="Address" className="max-w-full" />
          <img src="/imprint/email.svg" alt="Email" className="max-w-full" />
        </div>
      </Card>
    </div>
  );
}
