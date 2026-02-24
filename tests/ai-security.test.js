const express = require('express');
const request = require('supertest');

describe('AI endpoint security policy', () => {
  afterEach(() => {
    jest.resetModules();
    jest.clearAllMocks();
  });

  test('POST /api/ai/estimate always uses global endpoint (ignores user ai_endpoint)', async () => {
    const callAIProvider = jest.fn().mockResolvedValue({
      calories: 123,
      food: 'Test food',
      confidence: 'high',
      macros: { protein: 10, carbs: 10, fat: 5 },
    });

    jest.doMock('../src/middleware/auth', () => ({
      requireLogin: (req, _res, next) => {
        req.currentUser = {
          id: 1,
          ai_key: null,
          ai_endpoint: 'http://127.0.0.1:8080/should-never-be-used',
          macros_enabled: {},
          macro_goals: {},
        };
        next();
      },
    }));

    jest.doMock('../src/db/pool', () => ({
      getEffectiveSetting: jest.fn(async (key, fallback) => {
        if (key === 'ai_provider') return { value: 'openai' };
        if (key === 'ai_key') return { value: 'global-test-key' };
        if (key === 'ai_endpoint') return { value: 'https://api.openai.com/v1' };
        if (key === 'ai_model') return { value: 'gpt-4o-mini' };
        return { value: fallback || null };
      }),
    }));

    jest.doMock('../src/lib/ai', () => ({
      decryptApiKey: jest.fn((x) => x),
      getAIUsageToday: jest.fn(async () => 0),
      incrementAIUsage: jest.fn(async () => {}),
      getAIDailyLimit: jest.fn(async () => null),
      callAIProvider,
    }));

    jest.doMock('../src/lib/macros', () => ({
      getEnabledMacros: jest.fn(() => []),
    }));

    const aiRoutes = require('../src/routes/ai');
    const app = express();
    app.use(express.json({ limit: '10mb' }));
    app.use('/', aiRoutes);

    const res = await request(app)
      .post('/api/ai/estimate')
      .send({
        image: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB',
        context: 'test',
      })
      .expect(200);

    expect(res.body.ok).toBe(true);
    expect(callAIProvider).toHaveBeenCalledTimes(1);

    // callAIProvider(provider, apiKey, endpoint, ...)
    const endpointArg = callAIProvider.mock.calls[0][2];
    expect(endpointArg).toBe('https://api.openai.com/v1');
    expect(endpointArg).not.toContain('127.0.0.1');
  });

  // Settings route policy is covered via integration behavior in route tests.

});
