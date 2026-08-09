// ESLint flat config for the client, run in CI directly after the typecheck.
//
// tsc already rejects what the type system can see, so everything here is
// chosen for the class of mistake it does not catch: an `any` smuggled
// through a boundary, a hook called conditionally, an async handler wired
// where a void return is required. Type-aware rules get their type
// information from the project service against tsconfig.json.
//
// NOTE: typescript-eslint needs the classic JS compiler API, which the native
// TS 7 npm package no longer ships — that is why package.json pins
// `typescript` below 6.1 (and renovate.json holds it there).

import js from '@eslint/js';
import globals from 'globals';
import reactHooks from 'eslint-plugin-react-hooks';
import reactRefresh from 'eslint-plugin-react-refresh';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  // Build output only; everything else in the tree is hand-written.
  { ignores: ['dist'] },

  {
    files: ['**/*.{ts,tsx}'],
    extends: [
      js.configs.recommended,
      tseslint.configs.strictTypeChecked,
      tseslint.configs.stylisticTypeChecked,
      reactHooks.configs.flat.recommended,
      reactRefresh.configs.vite,
    ],
    languageOptions: {
      globals: globals.browser,
      parserOptions: {
        projectService: {
          // vite.config.ts, i18next.config.ts and the node-side tests sit
          // outside tsconfig.json's `include: ["src"]`. Lint them against a
          // default project rather than widening the tsconfig, which would
          // change what `tsc -b` typechecks.
          allowDefaultProject: [
            '*.config.ts',
            'tests/*.ts',
            'tests/fixtures/setup.ts',
          ],
        },
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      // — tuned, not disabled —

      // `onX={() => doThing()}` arrow-shorthand handlers are the pervasive
      // idiom here (186 findings). The confusion the rule guards against —
      // accidentally relying on a void return value — cannot arise when JSX
      // discards the result. Non-shorthand cases stay checked.
      '@typescript-eslint/no-confusing-void-expression': [
        'error',
        { ignoreArrowShorthand: true },
      ],

      // Async submit/click handlers are idiomatic React, and every one in
      // this tree try/catches its own awaits. `properties` covers the same
      // handlers when they travel through options objects (swipe-action
      // menus). Other void-return positions stay checked.
      '@typescript-eslint/no-misused-promises': [
        'error',
        { checksVoidReturn: { attributes: false, properties: false } },
      ],

      // Numbers interpolate deterministically; banning them would wrap every
      // `${count}` in String() for no safety gain. Everything else (objects,
      // arrays, nullish) is still rejected.
      '@typescript-eslint/restrict-template-expressions': [
        'error',
        { allowNumber: true },
      ],

      // The `_`-prefix is the codebase's existing marker for "accepted but
      // deliberately unused" (kept destructured props document a component's
      // full interface).
      '@typescript-eslint/no-unused-vars': [
        'error',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          caughtErrorsIgnorePattern: '^_',
        },
      ],

      // — deliberately off —
      //
      // Each of these fought an established idiom wholesale rather than
      // catching mistakes; the reasoning is recorded so the decision can be
      // revisited instead of re-litigated.

      // 85 findings, all the same shape: fire-and-forget calls whose errors
      // are handled elsewhere by design — queryClient.invalidateQueries
      // (settles through React Query, rejections surface in query state),
      // router navigate(), i18n.changeLanguage, and local async helpers that
      // try/catch internally (authStore.fetchUser, the handleSave family).
      // Prefixing every call site with `void` would be a wholesale reformat
      // that documents nothing.
      '@typescript-eslint/no-floating-promises': 'off',

      // The `||` fallbacks here are deliberate about falsiness: empty strings
      // from the API must fall through (`dashboard?.timeZone || 'UTC'`,
      // `data.unit || user?.weightUnit || 'kg'`). Converting to `??` is a
      // per-site semantic change, not a mechanical fix, so the rule mostly
      // proposes behaviour changes.
      '@typescript-eslint/prefer-nullish-coalescing': 'off',

      // Flags exactly the defensive guards this codebase wants to keep:
      // optional chains over Record lookups (tsconfig has no
      // noUncheckedIndexedAccess, so the type system believes every index
      // hit), fallbacks on API payload fields, `window.EventSource` feature
      // checks. Types lie at precisely those boundaries; deleting the guards
      // would trade runtime resilience for lint silence.
      '@typescript-eslint/no-unnecessary-condition': 'off',

      // Every empty function in the tree is a deliberate no-op: best-effort
      // `.catch(() => {})` on prefetches, a controlled-input onChange stub,
      // the intentionally never-settling Promise in lazyRoute's reload path.
      '@typescript-eslint/no-empty-function': 'off',

      // Every `=== true` / `!== false` on a boolean-typed value in this tree
      // is a runtime guard, not a tautology: macrosEnabled comes off the wire
      // typed Record<string, boolean> but can carry missing keys or 1/'yes',
      // and `!== false` vs `=== true` is how default-on vs default-off is
      // expressed (macros.test.ts pins this). All four findings were such
      // guards, and the rule's autofix silently inverted the calories
      // default — an actively dangerous fix for zero safety gain.
      '@typescript-eslint/no-unnecessary-boolean-literal-compare': 'off',

      // React-compiler-era rules that flag two pre-compiler idioms used
      // throughout: state synchronised from props/storage inside effects
      // (modal open/reset flows) and render-time reads of refs in custom
      // hooks. The fixes are per-component restructurings, not lint fixes —
      // revisit when the React Compiler is actually adopted.
      'react-hooks/set-state-in-effect': 'off',
      'react-hooks/refs': 'off',
    },
  },

  // Tests drive untyped surfaces on purpose: quagga2's decode callbacks,
  // package-lock JSON spelunking, hand-rolled module mocks, DOM nodes that
  // are known to exist. The unsafe-`any` family and `!` assertions there add
  // casts, not safety.
  {
    files: ['tests/**/*.ts', 'src/**/*.test.{ts,tsx}', 'src/test/**/*.ts'],
    rules: {
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
      '@typescript-eslint/no-unsafe-call': 'off',
      '@typescript-eslint/no-unsafe-argument': 'off',
      '@typescript-eslint/no-unsafe-return': 'off',
      '@typescript-eslint/no-non-null-assertion': 'off',
    },
  },

  // Plain JS at the edges: this config file and the maintenance scripts in
  // scripts/. No type information to lint against, so only the core set.
  {
    files: ['**/*.{js,mjs}'],
    extends: [js.configs.recommended],
    languageOptions: { globals: globals.node },
  },
);
