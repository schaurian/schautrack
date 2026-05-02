// Maps OIDC redirect error/success codes to human-readable messages.
// The server uses redirects (?error=... / ?success=...) for OIDC because
// the user is mid-redirect from the IdP — we can't return JSON to a fetch
// caller. The client reads the query params on /login and /settings load
// and surfaces them as toasts/alerts.

export const OIDC_LOGIN_ERRORS: Record<string, string> = {
  invalid_state: 'Login failed: invalid state. Please try again.',
  exchange_failed: 'Could not complete sign-in with your provider.',
  no_id_token: 'Sign-in provider returned no ID token.',
  verification_failed: 'Could not verify the sign-in token.',
  invalid_nonce: 'Login failed: invalid nonce. Please try again.',
  invalid_claims: 'Sign-in provider returned invalid information.',
  registration_disabled: 'Registration is currently disabled. Ask an admin for an invite.',
  no_email: 'Your sign-in provider did not return an email address.',
  internal: 'Something went wrong. Please try again.',
  create_failed: 'Could not create your account. Please try again.',
  link_failed: 'Could not link your sign-in provider. Please try again.',
};

export const OIDC_SETTINGS_ERRORS: Record<string, string> = {
  oidc_already_linked: 'That sign-in provider account is already linked to another user.',
  oidc_email_unverified:
    'Your sign-in provider did not confirm your email. Verify it there, then try again.',
  oidc_link_failed: 'Could not link your sign-in provider. Please try again.',
};

export const OIDC_SETTINGS_SUCCESS: Record<string, string> = {
  oidc_linked: 'Sign-in provider linked to your account.',
};
