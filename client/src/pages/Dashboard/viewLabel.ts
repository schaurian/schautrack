import type { SharedView } from '@/types';

/**
 * The name a shared view is shown under. The server sends the literal English
 * "You" as the self view's `label` (kept for API compatibility), so the self
 * view is named from the catalog instead — otherwise German reads "You" in the
 * timeline while the entries header says "Du".
 */
export function viewLabel(view: Pick<SharedView, 'isSelf' | 'label'>, translate: (key: string) => string): string {
  // Named `translate`, not `t`: the extractor would file this key under
  // the default `common` namespace. Callers pass the `dashboard` t.
  return view.isSelf ? translate('store.you') : view.label;
}
