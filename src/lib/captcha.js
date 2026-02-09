const svgCaptcha = require('svg-captcha');

// SVG CAPTCHA helper (self-hosted image captcha)
const generateCaptcha = () => {
  return svgCaptcha.create({
    size: 5,
    noise: 4,
    color: true,
    background: '#1a1a2e',
  });
};

const verifyCaptcha = (sessionAnswer, userAnswer) => {
  if (!sessionAnswer || !userAnswer) return false;
  return sessionAnswer.toLowerCase().trim() === userAnswer.toLowerCase().trim();
};

module.exports = {
  generateCaptcha,
  verifyCaptcha
};