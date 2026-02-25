const express = require('express');
const request = require('supertest');

describe('AI configuration', () => {
  afterEach(() => {
    jest.resetModules();
    jest.clearAllMocks();
  });

  test('POST /api/ai/estimate ignores user endpoint (admin-only)', async () => {
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
          ai_model: null,
          preferred_ai_provider: null,
          macros_enabled: {},
          macro_goals: {},
        };
        next();
      },
    }));

    jest.doMock('../src/db/pool', () => ({
      getEffectiveSetting: jest.fn(async (key) => {
        if (key === 'ai_provider') return { value: 'openai' };
        if (key === 'ai_key') return { value: 'global-test-key' };
        if (key === 'ai_endpoint') return { value: 'https://api.openai.com/v1' };
        if (key === 'ai_model') return { value: 'gpt-4o-mini' };
        return { value: null };
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

    // User endpoint must be ignored — only global endpoint is used
    const endpointArg = callAIProvider.mock.calls[0][2];
    expect(endpointArg).toBe('https://api.openai.com/v1');
    expect(endpointArg).not.toContain('127.0.0.1');
  });

  test('POST /api/ai/estimate uses user model over global', async () => {
    const callAIProvider = jest.fn().mockResolvedValue({
      calories: 300,
      food: 'Pasta',
      confidence: 'medium',
      macros: { protein: 12, carbs: 45, fat: 8 },
    });

    jest.doMock('../src/middleware/auth', () => ({
      requireLogin: (req, _res, next) => {
        req.currentUser = {
          id: 1,
          ai_key: null,
          ai_endpoint: null,
          ai_model: 'gpt-4o',
          preferred_ai_provider: null,
          macros_enabled: {},
          macro_goals: {},
        };
        next();
      },
    }));

    jest.doMock('../src/db/pool', () => ({
      getEffectiveSetting: jest.fn(async (key) => {
        if (key === 'ai_provider') return { value: 'openai' };
        if (key === 'ai_key') return { value: 'global-test-key' };
        if (key === 'ai_endpoint') return { value: null };
        if (key === 'ai_model') return { value: 'gpt-4o-mini' };
        return { value: null };
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

    // User model takes priority over global
    const modelArg = callAIProvider.mock.calls[0][6];
    expect(modelArg).toBe('gpt-4o');
  });

  test('POST /api/ai/estimate uses user preferred provider over global', async () => {
    const callAIProvider = jest.fn().mockResolvedValue({
      calories: 200,
      food: 'Salad',
      confidence: 'high',
      macros: { protein: 5, carbs: 15, fat: 3 },
    });

    jest.doMock('../src/middleware/auth', () => ({
      requireLogin: (req, _res, next) => {
        req.currentUser = {
          id: 1,
          ai_key: 'user-key',
          ai_endpoint: null,
          ai_model: 'claude-sonnet-4-5-20250929',
          preferred_ai_provider: 'claude',
          macros_enabled: {},
          macro_goals: {},
        };
        next();
      },
    }));

    jest.doMock('../src/db/pool', () => ({
      getEffectiveSetting: jest.fn(async (key) => {
        if (key === 'ai_provider') return { value: 'openai' };
        if (key === 'ai_key') return { value: 'global-test-key' };
        if (key === 'ai_endpoint') return { value: null };
        if (key === 'ai_model') return { value: 'gpt-4o-mini' };
        return { value: null };
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

    // User provider takes priority
    const providerArg = callAIProvider.mock.calls[0][0];
    expect(providerArg).toBe('claude');

    // User model takes priority
    const modelArg = callAIProvider.mock.calls[0][6];
    expect(modelArg).toBe('claude-sonnet-4-5-20250929');
  });
});
