const nodemailer = require('nodemailer');
const crypto = require('crypto');

// SMTP configuration
const smtpHost = process.env.SMTP_HOST;
const smtpPort = parseInt(process.env.SMTP_PORT || '587', 10);
const smtpUser = process.env.SMTP_USER;
const smtpPass = process.env.SMTP_PASS;
const smtpFrom = process.env.SMTP_FROM || process.env.SUPPORT_EMAIL;
const smtpSecure = process.env.SMTP_SECURE === 'true';

const isSmtpConfigured = () => Boolean(smtpHost && smtpUser && smtpPass && smtpFrom);

let smtpTransporter = null;
if (isSmtpConfigured()) {
  smtpTransporter = nodemailer.createTransport({
    host: smtpHost,
    port: smtpPort,
    secure: smtpSecure,
    auth: {
      user: smtpUser,
      pass: smtpPass,
    },
  });
}

const sendEmail = async (to, subject, text, html) => {
  if (!smtpTransporter) {
    throw new Error('SMTP not configured');
  }
  try {
    return await smtpTransporter.sendMail({
      from: smtpFrom,
      to,
      subject,
      text,
      html,
    });
  } catch (err) {
    // Log SMTP errors but don't expose them to users (privacy protection)
    console.warn('SMTP send failed:', err.message);
    return null;
  }
};

const generateResetCode = () => {
  return crypto.randomBytes(32).toString('hex');
};

const sendVerificationEmail = async (email, code) => {
  const subject = 'Verify Your Email - Schautrack';
  const text = `Your verification code is: ${code}\n\nThis code expires in 30 minutes.\n\nIf you did not create this account, you can ignore this email.`;
  const html = `
    <p>Your verification code is:</p>
    <h2 style="font-family: monospace; letter-spacing: 4px;">${code}</h2>
    <p>This code expires in 30 minutes.</p>
    <p>If you did not create this account, you can ignore this email.</p>
  `;
  await sendEmail(email, subject, text, html);
};

const sendEmailChangeVerification = async (email, code) => {
  const subject = 'Verify Your New Email - Schautrack';
  const text = `Your verification code is: ${code}\n\nThis code expires in 30 minutes.\n\nIf you did not request this email change, you can ignore this email.`;
  const html = `
    <p>Your verification code to confirm your new email address is:</p>
    <h2 style="font-family: monospace; letter-spacing: 4px;">${code}</h2>
    <p>This code expires in 30 minutes.</p>
    <p>If you did not request this email change, you can ignore this email.</p>
  `;
  await sendEmail(email, subject, text, html);
};

module.exports = {
  isSmtpConfigured,
  sendEmail,
  generateResetCode,
  sendVerificationEmail,
  sendEmailChangeVerification
};