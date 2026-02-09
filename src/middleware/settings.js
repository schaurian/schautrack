const { getEffectiveSetting } = require('../db/pool');

const loadGlobalSettings = async (req, res, next) => {
  res.locals.buildVersion = process.env.BUILD_VERSION || null;
  res.locals.robotsIndex = process.env.ROBOTS_INDEX === 'true';
  res.locals.baseUrl = process.env.BASE_URL || `${req.protocol}://${req.get('host')}`;

  // Load configurable settings (env vars take precedence over DB)
  const effectiveSupportEmail = await getEffectiveSetting('support_email', process.env.SUPPORT_EMAIL);
  const effectiveEnableLegal = await getEffectiveSetting('enable_legal', process.env.ENABLE_LEGAL);
  const effectiveImprintUrl = await getEffectiveSetting('imprint_url', process.env.IMPRINT_URL || '/imprint');
  const effectiveImprintAddress = await getEffectiveSetting('imprint_address', process.env.IMPRINT_ADDRESS);
  const effectiveImprintEmail = await getEffectiveSetting('imprint_email', process.env.IMPRINT_EMAIL);

  res.locals.supportEmail = effectiveSupportEmail.value || process.env.SUPPORT_EMAIL || null;

  // Only enable legal UI if flag is true AND we have the required content
  const legalEnabled = effectiveEnableLegal.value === 'true';
  const hasImprintContent = !!effectiveImprintAddress.value && !!effectiveImprintEmail.value;
  res.locals.enableLegal = legalEnabled && hasImprintContent;
  res.locals.imprintUrl = effectiveImprintUrl.value || '/imprint';
  next();
};

module.exports = {
  loadGlobalSettings
};