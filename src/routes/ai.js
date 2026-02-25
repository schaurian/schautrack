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
const { getEnabledMacros } = require('../lib/macros');

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

  // Reject oversized images (~10MB decoded limit)
  const MAX_BASE64_LENGTH = 14 * 1024 * 1024; // ~10MB decoded
  if (image.length > MAX_BASE64_LENGTH) {
    return res.status(413).json({ ok: false, error: 'Image too large. Maximum size is 10MB.' });
  }

  const user = req.currentUser;

  // Batch all global settings queries
  const [globalProvider, globalKey, globalEndpoint, globalModel] = await Promise.all([
    getEffectiveSetting('ai_provider', process.env.AI_PROVIDER),
    getEffectiveSetting('ai_key', process.env.AI_KEY),
    getEffectiveSetting('ai_endpoint', process.env.AI_ENDPOINT),
    getEffectiveSetting('ai_model', process.env.AI_MODEL),
  ]);

  // User's preferred provider takes priority over global
  const provider = user.preferred_ai_provider || globalProvider.value;

  if (!provider) {
    return res.status(400).json({ ok: false, error: 'No AI provider configured. Set your provider in settings or ask the admin to configure AI_PROVIDER.' });
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

  // Fallback to global settings
  if (!apiKey) {
    if (globalKey.value) {
      apiKey = globalKey.value;
      usingGlobalKey = true;
    }
  }

  // Endpoint is admin-only (global setting) — users cannot override
  if (globalEndpoint.value) {
    endpoint = globalEndpoint.value;
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

  // Rate limiting
  // Global key: admin-configured limit applies
  // Own key: user's personal daily limit applies (if set)
  const usageToday = await getAIUsageToday(user.id);
  if (usingGlobalKey) {
    const dailyLimit = await getAIDailyLimit();
    if (dailyLimit !== null && usageToday >= dailyLimit) {
      return res.status(429).json({
        ok: false,
        error: `Daily limit reached (${dailyLimit} requests). Add your own API key in settings for unlimited access.`,
        limitReached: true,
        limit: dailyLimit,
        used: usageToday,
      });
    }
  } else if (user.ai_daily_limit) {
    const userLimit = parseInt(user.ai_daily_limit, 10);
    if (!Number.isNaN(userLimit) && userLimit > 0 && usageToday >= userLimit) {
      return res.status(429).json({
        ok: false,
        error: `Daily limit reached (${userLimit} requests). Increase your limit in settings.`,
        limitReached: true,
        limit: userLimit,
        used: usageToday,
      });
    }
  }

  const base64Data = image.replace(/^data:image\/\w+;base64,/, '');
  const mediaType = image.match(/^data:(image\/\w+);base64,/)?.[1] || 'image/jpeg';

  // Get custom model: user's personal model, then global
  let customModel = null;
  if (user.ai_model) {
    customModel = user.ai_model;
  } else if (globalModel.value) {
    customModel = globalModel.value;
  }

  // Provider-specific model validation
  if (provider === 'openai' || provider === 'claude') {
    if (!customModel) {
      return res.status(400).json({
        ok: false,
        error: `${provider === 'openai' ? 'OpenAI' : 'Claude'} requires AI_MODEL to be configured (e.g., ${provider === 'openai' ? 'gpt-4o-mini' : 'claude-sonnet-4-5-20250929'})`
      });
    }
  }

  const contextHint = context ? `\n\nUser provided context: "${context}"` : '';

  // Get user's enabled macros (for returning to client)
  const enabledMacros = getEnabledMacros(user);

  // Always request protein/carbs/fat (needed for auto-calc calories), plus any other enabled macros
  const requestedMacros = new Set(['protein', 'carbs', 'fat']);
  for (const key of enabledMacros) requestedMacros.add(key);
  const macroList = [...requestedMacros].join(', ');
  const macroExample = [...requestedMacros].map((k) => `"${k}": ${k === 'protein' ? 25 : k === 'carbs' ? 40 : k === 'fat' ? 12 : k === 'fiber' ? 5 : 8}`).join(', ');

  const prompt = `Analyze this food image and estimate the calories.${contextHint}

Also estimate these macros (in grams, as whole numbers): ${macroList}.

Respond in JSON format with these fields:
- calories: estimated total calories (number, must be > 0 if food is detected)
- food: brief description of the food items (string, max 50 chars)
- confidence: your confidence level ("high", "medium", or "low")
- macros: object with estimated values in grams for: ${macroList} (e.g., {${macroExample}})

IMPORTANT: These are estimates only. Actual nutritional values may vary significantly based on portion size, preparation method, and ingredients.

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

    // Increment usage after successful request
    // Track for global key users (admin limit) AND own-key users with personal limit
    if (usingGlobalKey || user.ai_daily_limit) {
      await incrementAIUsage(user.id);
    }

    // Compute calories from macros (protein*4 + carbs*4 + fat*9) when available
    const p = parseInt(result.macros?.protein, 10) || 0;
    const c = parseInt(result.macros?.carbs, 10) || 0;
    const f = parseInt(result.macros?.fat, 10) || 0;
    const macroCalories = (p * 4) + (c * 4) + (f * 9);
    const calories = macroCalories > 0 ? macroCalories : result.calories;

    // Only return macros the user has enabled in their settings
    let macros = null;
    if (enabledMacros.length > 0 && result.macros) {
      macros = {};
      for (const key of enabledMacros) {
        const value = parseInt(result.macros[key], 10);
        macros[key] = Number.isNaN(value) ? null : value;
      }
    }

    return res.json({
      ok: true,
      calories,
      food: result.food,
      confidence: result.confidence,
      macros,
      disclaimer: enabledMacros.length > 0
        ? 'Macro estimates are approximate. Actual values may vary based on portion size and preparation.'
        : null,
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