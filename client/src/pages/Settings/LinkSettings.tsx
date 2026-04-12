import { useState } from 'react';
import type { LinkRequest, AcceptedLink } from '@/types';
import { requestLink, respondToLink, removeLink, updateLinkLabel } from '@/api/links';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Card } from '@/components/ui/Card';
import { useToastStore } from '@/stores/toastStore';

interface Props {
  incomingRequests: LinkRequest[];
  outgoingRequests: LinkRequest[];
  acceptedLinks: AcceptedLink[];
  availableSlots: number;
  onUpdate: () => void;
}

export default function LinkSettings({ incomingRequests, outgoingRequests, acceptedLinks, availableSlots, onUpdate }: Props) {
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const addToast = useToastStore((s) => s.addToast);

  const handleRequest = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      await requestLink(email);
      setEmail('');
      onUpdate();
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : 'Failed to send link request');
    }
    setLoading(false);
  };

  const handleRespond = async (linkId: number, action: 'accept' | 'decline') => {
    try {
      await respondToLink(linkId, action);
      onUpdate();
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : 'Failed to respond to link');
    }
  };

  const handleRemove = async (linkId: number) => {
    try {
      await removeLink(linkId);
      onUpdate();
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : 'Failed to remove link');
    }
  };

  return (
    <Card>
      <h3 className="text-base font-semibold mb-4">Account Links</h3>

      {incomingRequests.length > 0 && (
        <div className="mb-4">
          <h4 className="text-xs uppercase tracking-wider text-muted-foreground mb-2">Incoming</h4>
          {incomingRequests.map((req) => (
            <div key={req.id} className="flex items-center gap-2 mb-2 text-sm">
              <span className="flex-1">{req.email}</span>
              <Button size="sm" onClick={() => handleRespond(req.id, 'accept')}>Accept</Button>
              <Button size="sm" variant="ghost" onClick={() => handleRespond(req.id, 'decline')}>Decline</Button>
            </div>
          ))}
        </div>
      )}

      {outgoingRequests.length > 0 && (
        <div className="mb-4">
          <h4 className="text-xs uppercase tracking-wider text-muted-foreground mb-2">Pending</h4>
          {outgoingRequests.map((req) => (
            <div key={req.id} className="flex items-center gap-2 mb-2 text-sm">
              <span className="flex-1">{req.email}</span>
              <Button size="sm" variant="ghost" onClick={() => handleRemove(req.id)}>Cancel</Button>
            </div>
          ))}
        </div>
      )}

      {acceptedLinks.length > 0 && (
        <div className="mb-4">
          <h4 className="text-xs uppercase tracking-wider text-muted-foreground mb-2">Linked</h4>
          {acceptedLinks.map((link) => (
            <LinkRow key={link.linkId} link={link} onRemove={() => handleRemove(link.linkId)} />
          ))}
        </div>
      )}

      {availableSlots > 0 && (
        <form onSubmit={handleRequest} className="flex flex-col gap-2">
          <Input label="Link by email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
          <div className="border-t border-border pt-3 mt-1">
            <Button type="submit" className="w-full" loading={loading}>Send Request</Button>
          </div>
        </form>
      )}
    </Card>
  );
}

function LinkRow({ link, onRemove }: { link: AcceptedLink; onRemove: () => void }) {
  const [editing, setEditing] = useState(false);
  const [label, setLabel] = useState(link.label || '');

  const addToast = useToastStore((s) => s.addToast);

  const saveLabel = async () => {
    try {
      await updateLinkLabel(link.linkId, label);
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : 'Failed to update label');
    }
    setEditing(false);
  };

  return (
    <div className="flex items-center gap-2 mb-2 text-sm">
      {editing ? (
        <input
          value={label}
          onChange={(e) => setLabel(e.target.value)}
          onBlur={saveLabel}
          onKeyDown={(e) => e.key === 'Enter' && saveLabel()}
          autoFocus
          className="flex-1 rounded border border-ring bg-muted/50 px-2 py-0.5 text-sm text-foreground outline-none"
        />
      ) : (
        <button type="button" onClick={() => setEditing(true)} className="flex-1 bg-transparent border-none text-foreground cursor-pointer text-left text-sm">
          {link.label || link.email}
        </button>
      )}
      <Button size="sm" variant="destructive" onClick={onRemove}>Remove</Button>
    </div>
  );
}
