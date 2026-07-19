import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { LinkRequest, AcceptedLink, LinkShares } from '@/types';
import { requestLink, respondToLink, removeLink, updateLinkLabel, setLinkShares } from '@/api/links';
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
  const { t } = useTranslation('settings');
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
      addToast('error', err instanceof Error ? err.message : t('link.requestFailed'));
    }
    setLoading(false);
  };

  const handleRespond = async (linkId: number, action: 'accept' | 'decline') => {
    try {
      await respondToLink(linkId, action);
      onUpdate();
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : t('link.respondFailed'));
    }
  };

  const handleRemove = async (linkId: number) => {
    try {
      await removeLink(linkId);
      onUpdate();
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : t('link.removeFailed'));
    }
  };

  return (
    <Card>
      <h3 className="text-base font-semibold mb-4">{t('link.heading')}</h3>

      {incomingRequests.length > 0 && (
        <div className="mb-4">
          <h4 className="text-xs uppercase tracking-wider text-muted-foreground mb-2">{t('link.incoming')}</h4>
          {incomingRequests.map((req) => (
            <div key={req.id} className="flex items-center gap-2 mb-2 text-sm">
              <span className="flex-1">{req.email}</span>
              <Button size="sm" onClick={() => handleRespond(req.id, 'accept')}>{t('link.accept')}</Button>
              <Button size="sm" variant="ghost" onClick={() => handleRespond(req.id, 'decline')}>{t('link.decline')}</Button>
            </div>
          ))}
        </div>
      )}

      {outgoingRequests.length > 0 && (
        <div className="mb-4">
          <h4 className="text-xs uppercase tracking-wider text-muted-foreground mb-2">{t('link.pending')}</h4>
          {outgoingRequests.map((req) => (
            <div key={req.id} className="flex items-center gap-2 mb-2 text-sm">
              <span className="flex-1">{req.email}</span>
              <Button size="sm" variant="ghost" onClick={() => handleRemove(req.id)}>{t('link.cancel')}</Button>
            </div>
          ))}
        </div>
      )}

      {acceptedLinks.length > 0 && (
        <div className="mb-4">
          <h4 className="text-xs uppercase tracking-wider text-muted-foreground mb-2">{t('link.linked')}</h4>
          {acceptedLinks.map((link) => (
            <LinkRow key={link.linkId} link={link} onRemove={() => handleRemove(link.linkId)} onUpdate={onUpdate} />
          ))}
        </div>
      )}

      {availableSlots > 0 && (
        <form onSubmit={handleRequest} className="flex flex-col gap-2">
          <Input label={t('link.requestLabel')} type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
          <div className="border-t border-border pt-3 mt-1">
            <Button type="submit" className="w-full" loading={loading}>{t('link.sendRequest')}</Button>
          </div>
        </form>
      )}
    </Card>
  );
}

function LinkRow({ link, onRemove, onUpdate }: { link: AcceptedLink; onRemove: () => void; onUpdate: () => void }) {
  const { t } = useTranslation('settings');
  const [editing, setEditing] = useState(false);
  const [label, setLabel] = useState(link.label || '');
  const [shares, setShares] = useState<LinkShares>(link.shares);
  const addToast = useToastStore((s) => s.addToast);

  const saveLabel = async () => {
    try {
      await updateLinkLabel(link.linkId, label);
      // Refresh the settings query so the edited label doesn't visually
      // revert to the stale server copy on the next render.
      onUpdate();
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : t('link.labelUpdateFailed'));
    }
    setEditing(false);
  };

  const toggleShare = async (cat: keyof LinkShares) => {
    const next = { ...shares, [cat]: !shares[cat] };
    setShares(next); // optimistic
    try {
      const res = await setLinkShares(link.linkId, next);
      setShares(res.shares);
    } catch (err) {
      setShares(shares); // revert
      addToast('error', err instanceof Error ? err.message : t('link.share.updateFailed'));
    }
  };

  const CATS: { key: keyof LinkShares; label: string }[] = [
    { key: 'nutrition', label: t('link.share.nutrition') },
    { key: 'weight', label: t('link.share.weight') },
    { key: 'todos', label: t('link.share.todos') },
    { key: 'notes', label: t('link.share.notes') },
  ];

  return (
    <div className="mb-3 border-b border-border pb-3 last:border-0">
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
        <Button size="sm" variant="destructive" onClick={onRemove}>{t('link.remove')}</Button>
      </div>
      <div className="text-xs text-muted-foreground mb-1">{t('link.share.readOnlyNote')}</div>
      <div className="flex flex-wrap gap-x-4 gap-y-1">
        {CATS.map(({ key, label: catLabel }) => (
          <label key={key} className="flex items-center gap-1.5 text-sm cursor-pointer">
            <input type="checkbox" checked={shares[key]} onChange={() => toggleShare(key)} />
            {catLabel}
          </label>
        ))}
      </div>
    </div>
  );
}
