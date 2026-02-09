const crypto = require('crypto');
const { pool, getEffectiveSetting } = require('../db/pool');

// API Key Encryption (AES-256-GCM)
const AI_KEY_ENCRYPTION_SECRET = process.env.AI_KEY_ENCRYPTION_SECRET;

const encryptApiKey = (plaintext) => {
  if (!AI_KEY_ENCRYPTION_SECRET || !plaintext) return null;
  try {
    const key = Buffer.from(AI_KEY_ENCRYPTION_SECRET, 'hex');
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    let encrypted = cipher.update(plaintext, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    const authTag = cipher.getAuthTag();
    return `${iv.toString('base64')}:${authTag.toString('base64')}:${encrypted}`;
  } catch (err) {
    console.error('Failed to encrypt API key', err);
    return null;
  }
};

const decryptApiKey = (ciphertext) => {
  if (!AI_KEY_ENCRYPTION_SECRET || !ciphertext) return null;
  try {
    const [ivB64, tagB64, encrypted] = ciphertext.split(':');
    const key = Buffer.from(AI_KEY_ENCRYPTION_SECRET, 'hex');
    const iv = Buffer.from(ivB64, 'base64');
    const authTag = Buffer.from(tagB64, 'base64');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(encrypted, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (err) {
    console.error('Failed to decrypt API key', err);
    return null;
  }
};

// AI Provider Configurations
const AI_PROVIDER_CONFIGS = {
  openai: {
    defaultEndpoint: 'https://api.openai.com/v1',
    model: 'gpt-4o-mini',
    authHeader: (key) => ({ 'Authorization': `Bearer ${key}` }),
    formatMessages: (prompt, base64Data, mediaType) => [{
      role: 'user',
      content: [
        { type: 'text', text: prompt },
        {
          type: 'image_url',
          image_url: {
            url: `data:${mediaType};base64,${base64Data}`,
            detail: 'low'
          }
        }
      ]
    }],
    getEndpointPath: () => '/chat/completions',
    parseResponse: (data) => data.choices[0]?.message?.content
  },

  claude: {
    defaultEndpoint: 'https://api.anthropic.com/v1',
    model: null, // No default - must be specified via AI_MODEL
    authHeader: (key) => ({
      'x-api-key': key,
      'anthropic-version': '2023-06-01'
    }),
    formatMessages: (prompt, base64Data, mediaType) => [{
      role: 'user',
      content: [
        {
          type: 'image',
          source: {
            type: 'base64',
            media_type: mediaType,
            data: base64Data
          }
        },
        { type: 'text', text: prompt }
      ]
    }],
    getEndpointPath: () => '/messages',
    parseResponse: (data) => data.content[0]?.text
  },

  ollama: {
    defaultEndpoint: 'http://localhost:11434/v1',
    model: 'gemma3:12b',
    authHeader: (key) => ({ 'Authorization': `Bearer ${key || 'ollama'}` }),
    formatMessages: (prompt, base64Data, mediaType) => [{
      role: 'user',
      content: [
        { type: 'text', text: prompt },
        {
          type: 'image_url',
          image_url: {
            url: `data:${mediaType};base64,${base64Data}`
          }
        }
      ]
    }],
    getEndpointPath: () => '/chat/completions',
    parseResponse: (data) => data.choices[0]?.message?.content
  }
};

// AI usage tracking helpers
const getAIUsageToday = async (userId) => {
  const result = await pool.query(
    'SELECT request_count FROM ai_usage WHERE user_id = $1 AND usage_date = CURRENT_DATE',
    [userId]
  );
  return result.rows[0]?.request_count || 0;
};

const incrementAIUsage = async (userId) => {
  await pool.query(`
    INSERT INTO ai_usage (user_id, usage_date, request_count)
    VALUES ($1, CURRENT_DATE, 1)
    ON CONFLICT (user_id, usage_date) DO UPDATE SET request_count = ai_usage.request_count + 1
  `, [userId]);
};

const getAIDailyLimit = async () => {
  const setting = await getEffectiveSetting('ai_daily_limit', process.env.AI_DAILY_LIMIT);
  const limit = parseInt(setting.value, 10);
  return Number.isNaN(limit) || limit <= 0 ? null : limit; // null means unlimited
};

async function callAIProvider(providerName, apiKey, endpoint, base64Data, mediaType, prompt, customModel = null) {
  const config = AI_PROVIDER_CONFIGS[providerName];
  if (!config) throw new Error(`Unknown provider: ${providerName}`);

  const controller = new AbortController();
  // Set timeout based on provider: 60s for Ollama (local), 30s for others (cloud)
  const timeoutMs = providerName === 'ollama' ? 60000 : 30000;
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const messages = config.formatMessages(prompt, base64Data, mediaType);
    const body = {
      model: customModel || config.model, // Use custom model if provided, otherwise use default
      messages: messages,
      max_tokens: 200
    };

    const baseUrl = endpoint || config.defaultEndpoint;
    const url = `${baseUrl}${config.getEndpointPath()}`;

    const response = await fetch(url, {
      method: 'POST',
      headers: {
        ...config.authHeader(apiKey),
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(body),
      signal: controller.signal
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`${providerName} API error (${response.status}): ${errorText}`);
    }

    const data = await response.json();
    const content = config.parseResponse(data);

    if (!content) {
      throw new Error(`No content in ${providerName} response`);
    }

    return parseAIResponse(content);
  } catch (err) {
    if (err.name === 'AbortError') {
      throw new Error('Request timed out. Please try again.');
    }
    throw err;
  } finally {
    clearTimeout(timeout);
  }
}

function parseAIResponse(content) {
  if (!content || typeof content !== 'string') {
    throw new Error('Empty AI response');
  }

  // Remove markdown code blocks if present
  let cleaned = content.replace(/```json\s*/gi, '').replace(/```\s*/g, '').trim();

  const jsonMatch = cleaned.match(/\{[\s\S]*\}/);
  if (!jsonMatch) {
    console.error('AI response without JSON:', content);
    throw new Error('Could not parse AI response');
  }

  try {
    const parsed = JSON.parse(jsonMatch[0]);

    const calories = parseInt(parsed.calories, 10);
    if (isNaN(calories) || calories <= 0) {
      // AI couldn't identify food - return specific error
      const reason = parsed.food || 'No food detected';
      const noFoodError = new Error('NO_FOOD_DETECTED');
      noFoodError.reason = reason;
      throw noFoodError;
    }

    return {
      calories,
      food: String(parsed.food || 'Unknown food').slice(0, 50),
      confidence: ['high', 'medium', 'low'].includes(parsed.confidence) ? parsed.confidence : 'medium',
    };
  } catch (parseErr) {
    if (parseErr.message === 'NO_FOOD_DETECTED') {
      throw parseErr;
    }
    console.error('JSON parse error:', parseErr.message, 'Content:', content);
    throw new Error('Could not understand AI response');
  }
}

// Validate AI configuration at startup
async function validateAIConfig() {
  const provider = await getEffectiveSetting('ai_provider', process.env.AI_PROVIDER);

  // If no provider is set, skip AI validation (AI features are disabled)
  if (!provider.value) {
    return;
  }

  // Validate provider is valid
  if (!['openai', 'claude', 'ollama'].includes(provider.value)) {
    console.error('');
    console.error('═══════════════════════════════════════════════════════════════');
    console.error('  STARTUP ERROR: Invalid AI Configuration');
    console.error('═══════════════════════════════════════════════════════════════');
    console.error('');
    console.error(`  AI_PROVIDER is set to '${provider.value}' but must be one of: openai, claude, ollama`);
    console.error('');
    console.error('═══════════════════════════════════════════════════════════════');
    console.error('');
    process.exit(1);
  }

  // OpenAI and Claude require API key + model
  if (provider.value === 'openai' || provider.value === 'claude') {
    const apiKey = await getEffectiveSetting('ai_key', process.env.AI_KEY);
    const model = await getEffectiveSetting('ai_model', process.env.AI_MODEL);

    const providerName = provider.value === 'openai' ? 'OpenAI' : 'Claude';
    const exampleModel = provider.value === 'openai' ? 'gpt-4o-mini' : 'claude-sonnet-4-20250514';

    if (!apiKey.value || !model.value) {
      console.error('');
      console.error('═══════════════════════════════════════════════════════════════');
      console.error('  STARTUP ERROR: Invalid AI Configuration');
      console.error('═══════════════════════════════════════════════════════════════');
      console.error('');
      console.error(`  AI_PROVIDER is set to '${provider.value}' but required configuration is missing:`);
      console.error('');
      if (!apiKey.value) console.error('  ✗ AI_KEY is not set');
      if (!model.value) console.error('  ✗ AI_MODEL is not set');
      console.error('');
      console.error(`  ${providerName} requires both AI_KEY and AI_MODEL to be configured.`);
      console.error('');
      console.error('  Example configuration:');
      console.error(`    AI_PROVIDER=${provider.value}`);
      console.error(`    AI_KEY=sk-...`);
      console.error(`    AI_MODEL=${exampleModel}`);
      console.error('');
      console.error('  Please set these in your environment variables or .env file.');
      console.error('');
      console.error('═══════════════════════════════════════════════════════════════');
      console.error('');
      process.exit(1);
    }
  }

  // Ollama requires endpoint
  if (provider.value === 'ollama') {
    const endpoint = await getEffectiveSetting('ai_endpoint', process.env.AI_ENDPOINT);

    if (!endpoint.value) {
      console.error('');
      console.error('═══════════════════════════════════════════════════════════════');
      console.error('  STARTUP ERROR: Invalid AI Configuration');
      console.error('═══════════════════════════════════════════════════════════════');
      console.error('');
      console.error(`  AI_PROVIDER is set to 'ollama' but AI_ENDPOINT is not configured.`);
      console.error('');
      console.error('  Ollama requires AI_ENDPOINT to be set.');
      console.error('');
      console.error('  Example configuration:');
      console.error('    AI_PROVIDER=ollama');
      console.error('    AI_ENDPOINT=http://ollama:11434/v1');
      console.error('');
      console.error('  Please set AI_ENDPOINT in your environment variables or .env file.');
      console.error('');
      console.error('═══════════════════════════════════════════════════════════════');
      console.error('');
      process.exit(1);
    }
  }
}

module.exports = {
  encryptApiKey,
  decryptApiKey,
  AI_PROVIDER_CONFIGS,
  getAIUsageToday,
  incrementAIUsage,
  getAIDailyLimit,
  callAIProvider,
  parseAIResponse,
  validateAIConfig
};