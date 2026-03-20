import { api } from './client';

interface LoginResponse {
  ok: boolean;
  requireToken?: boolean;
  requireVerification?: boolean;
  requireCaptcha?: boolean;
  captchaSvg?: string;
  error?: string;
}

interface RegisterResponse {
  ok: boolean;
  requireCaptcha?: boolean;
  requireVerification?: boolean;
  requireInviteCode?: boolean;
  captchaSvg?: string;
  error?: string;
}

export function login(data: { email: string; password: string; token?: string; captcha?: string }) {
  return api<LoginResponse>('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export function register(data: { step: string; email?: string; password?: string; timezone?: string; captcha?: string; invite_code?: string }) {
  return api<RegisterResponse>('/api/auth/register', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export function getRegistrationInfo() {
  return api<{ registrationMode: string }>('/api/auth/registration-info');
}

export function logout() {
  return api<{ ok: boolean }>('/api/auth/logout', { method: 'POST' });
}

export function forgotPassword(data: { email: string; captcha: string }) {
  return api<{ ok: boolean; error?: string; captchaSvg?: string }>('/api/auth/forgot-password', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export function resetPassword(data: { code?: string; password?: string; confirm_password?: string }) {
  return api<{ ok: boolean; codeVerified?: boolean; error?: string }>('/api/auth/reset-password', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export function verifyEmail(data: { code: string }) {
  return api<{ ok: boolean; error?: string }>('/api/auth/verify-email', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export function resendVerification(data: { captcha?: string }) {
  return api<{ ok: boolean; nextRequiresCaptcha?: boolean; captchaSvg?: string; cooldown?: number; error?: string }>('/api/auth/verify-email/resend', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export function getCaptcha() {
  return api<{ svg: string }>('/api/auth/captcha');
}

export function getMe() {
  return api<{ user: import('@/types').User; isAdmin: boolean }>('/api/me');
}
