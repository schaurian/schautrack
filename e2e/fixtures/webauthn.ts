import type { BrowserContext, Page } from '@playwright/test';

/**
 * Attach a virtual WebAuthn authenticator to the browser context via CDP.
 * Subsequent navigator.credentials.create()/get() calls resolve against this
 * in-memory authenticator, no real biometric or USB key needed.
 *
 * Returns the authenticator id and a teardown function that removes it.
 */
export async function attachVirtualAuthenticator(
  context: BrowserContext,
  page: Page,
): Promise<{ authenticatorId: string; teardown: () => Promise<void> }> {
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      // CTAP2 is required for resident-key (passkey) credentials.
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  return {
    authenticatorId,
    teardown: async () => {
      try {
        await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId });
      } catch {
        /* context may already be closed */
      }
      try { await cdp.detach(); } catch { /* ignore */ }
    },
  };
}
