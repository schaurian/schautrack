const express = require('express');
const rateLimit = require('express-rate-limit');
const { requireLogin } = require('../middleware/auth');
const { getEffectiveSetting } = require('../db/pool');
const {
  decryptApiKey,
  getAIUsageToday,
  incrementAIUsage,
  getAIDailyLimit,
  callAIProvider
} = require('../lib/ai');

const router = express.Router();

const strictLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 5, // max 5 attempts per windowMs
  message: { error: 'Too many attempts. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  validate: { trustProxy: false },
});

// AI Calorie Estimation API
router.post('/api/ai/estimate', strictLimiter, requireLogin, async (req, res) => {
  const { image, context } = req.body;

  if (!image || !image.startsWith('data:image/')) {
    return res.status(400).json({ ok: false, error: 'Invalid image data' });
  }

  const user = req.currentUser;

  // Determine provider from global setting only
  const globalProvider = await getEffectiveSetting('ai_provider', process.env.AI_PROVIDER);
  const provider = globalProvider.value;

  if (!provider) {
    return res.status(400).json({ ok: false, error: 'AI_PROVIDER must be configured (openai, claude, or ollama)' });
  }

  if (!['openai', 'claude', 'ollama'].includes(provider)) {
    return res.status(400).json({ ok: false, error: 'Invalid provider' });
  }

  // Get unified API key and endpoint
  let apiKey = null;
  let endpoint = null;
  let usingGlobalKey = false;

  // User's personal key
  if (user.ai_key) {
    apiKey = decryptApiKey(user.ai_key);
  }

  // User's custom endpoint
  if (user.ai_endpoint) {
    endpoint = user.ai_endpoint;
  }

  // Fallback to global settings
  if (!apiKey) {
    const globalKey = await getEffectiveSetting('ai_key', process.env.AI_KEY);
    if (globalKey.value) {
      apiKey = globalKey.value;
      usingGlobalKey = true;
    }
  }

  if (!endpoint) {
    const globalEndpoint = await getEffectiveSetting('ai_endpoint', process.env.AI_ENDPOINT);
    if (globalEndpoint.value) {
      endpoint = globalEndpoint.value;
    }
  }

  // Provider-specific validation
  if (provider === 'openai' || provider === 'claude') {
    // OpenAI and Claude require API key
    if (!apiKey) {
      return res.status(400).json({
        ok: false,
        error: `${provider === 'openai' ? 'OpenAI' : 'Claude'} requires an API key. Please configure AI_KEY.`
      });
    }
  }

  if (provider === 'ollama') {
    // Ollama requires endpoint
    if (!endpoint) {
      return res.status(400).json({
        ok: false,
        error: 'Ollama requires AI_ENDPOINT to be configured (e.g., http://ollama:11434/v1)'
      });
    }
    // Ollama: API key is optional
    if (!apiKey) {
      apiKey = 'ollama';
      usingGlobalKey = true; // Count Ollama usage as global
    }
  }

  // Rate limiting: only applies when using global key
  if (usingGlobalKey) {
    const dailyLimit = await getAIDailyLimit();
    if (dailyLimit !== null) {
      const usageToday = await getAIUsageToday(user.id);
      if (usageToday >= dailyLimit) {
        return res.status(429).json({
          ok: false,
          error: `Daily limit reached (${dailyLimit} requests). Add your own API key in settings for unlimited access.`,
          limitReached: true,
          limit: dailyLimit,
          used: usageToday,
        });
      }
    }
  }

  const base64Data = image.replace(/^data:image\/\w+;base64,/, '');
  const mediaType = image.match(/^data:(image\/\w+);base64,/)?.[1] || 'image/jpeg';

  // Get custom model from settings/env
  let customModel = null;
  const globalModel = await getEffectiveSetting('ai_model', process.env.AI_MODEL);
  if (globalModel.value) {
    customModel = globalModel.value;
  }

  // Provider-specific model validation
  if (provider === 'openai' || provider === 'claude') {
    if (!customModel) {
      return res.status(400).json({
        ok: false,
        error: `${provider === 'openai' ? 'OpenAI' : 'Claude'} requires AI_MODEL to be configured (e.g., ${provider === 'openai' ? 'gpt-4o-mini' : 'claude-sonnet-4-20250514'})`
      });
    }
  }

  const contextHint = context ? `\n\nUser provided context: "${context}"` : '';
  const prompt = `Analyze this food image and estimate the calories.${contextHint}

Respond in JSON format with these fields:
- calories: estimated total calories (number, must be > 0 if food is detected). Round to nearest 50 for values >= 50.
- food: brief description of the food items (string, max 50 chars)
- confidence: your confidence level ("high", "medium", or "low")

If you cannot identify any food in the image, set calories to 0 and food to "No food detected".

Only respond with the JSON object, no other text.`;

  try {
    const result = await callAIProvider(
      provider,
      apiKey,
      endpoint,
      base64Data,
      mediaType,
      prompt,
      customModel
    );

    // Increment usage after successful request (only for global key)
    if (usingGlobalKey) {
      await incrementAIUsage(user.id);
    }

    // Round calories: keep exact if <50, otherwise round to nearest 50
    const rawCalories = result.calories;
    const calories = rawCalories < 50 ? rawCalories : Math.round(rawCalories / 50) * 50;

    return res.json({
      ok: true,
      calories,
      food: result.food,
      confidence: result.confidence,
    });
  } catch (err) {
    console.error('AI estimation failed:', err.message);
    if (err.message === 'NO_FOOD_DETECTED') {
      return res.status(400).json({
        ok: false,
        error: 'Could not identify food in the image. Try taking a clearer photo or use manual entry.',
        code: 'NO_FOOD',
      });
    }
    return res.status(500).json({ ok: false, error: err.message || 'AI analysis failed' });
  }
});

module.exports = router;