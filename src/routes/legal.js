const express = require('express');
const { getEffectiveSetting } = require('../db/pool');
const { textToSvg } = require('../lib/utils');

const router = express.Router();

router.get('/imprint/address.svg', async (req, res) => {
  const effectiveEnableLegal = await getEffectiveSetting('enable_legal', process.env.ENABLE_LEGAL);
  const effectiveImprintAddress = await getEffectiveSetting('imprint_address', process.env.IMPRINT_ADDRESS);
  if (effectiveEnableLegal.value !== 'true' || !effectiveImprintAddress.value) return res.sendStatus(404);
  res.setHeader('Content-Type', 'image/svg+xml');
  res.setHeader('Cache-Control', 'no-store');
  res.send(textToSvg(effectiveImprintAddress.value));
});

router.get('/imprint/email.svg', async (req, res) => {
  const effectiveEnableLegal = await getEffectiveSetting('enable_legal', process.env.ENABLE_LEGAL);
  const effectiveImprintEmail = await getEffectiveSetting('imprint_email', process.env.IMPRINT_EMAIL);
  if (effectiveEnableLegal.value !== 'true' || !effectiveImprintEmail.value) return res.sendStatus(404);
  res.setHeader('Content-Type', 'image/svg+xml');
  res.setHeader('Cache-Control', 'no-store');
  res.send(textToSvg(effectiveImprintEmail.value));
});

router.get('/imprint', async (req, res) => {
  const effectiveEnableLegal = await getEffectiveSetting('enable_legal', process.env.ENABLE_LEGAL);
  const effectiveImprintAddress = await getEffectiveSetting('imprint_address', process.env.IMPRINT_ADDRESS);
  const effectiveImprintEmail = await getEffectiveSetting('imprint_email', process.env.IMPRINT_EMAIL);

  if (effectiveEnableLegal.value !== 'true' || !effectiveImprintAddress.value || !effectiveImprintEmail.value) return res.sendStatus(404);
  res.render('imprint', { activePage: null });
});

router.get('/privacy', async (req, res) => {
  const effectiveEnableLegal = await getEffectiveSetting('enable_legal', process.env.ENABLE_LEGAL);
  if (effectiveEnableLegal.value !== 'true') return res.sendStatus(404);
  res.render('privacy', { activePage: null });
});

router.get('/terms', async (req, res) => {
  const effectiveEnableLegal = await getEffectiveSetting('enable_legal', process.env.ENABLE_LEGAL);
  if (effectiveEnableLegal.value !== 'true') return res.sendStatus(404);
  res.render('terms', { activePage: null });
});

router.get('/delete', async (req, res) => {
  const effectiveEnableLegal = await getEffectiveSetting('enable_legal', process.env.ENABLE_LEGAL);
  if (effectiveEnableLegal.value !== 'true') return res.sendStatus(404);
  const feedback = req.session.deleteFeedback || null;
  delete req.session.deleteFeedback;
  res.render('delete', { activePage: null, deleteFeedback: feedback });
});

module.exports = router;