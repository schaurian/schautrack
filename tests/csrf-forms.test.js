const { describe, test, expect } = require('@jest/globals');
const fs = require('fs');
const path = require('path');

// Routes that use csrfProtection middleware (from src/routes/)
const CSRF_PROTECTED_ACTIONS = [
  '/register',
  '/login',
  '/forgot-password',
  '/reset-password',
  '/entries',
  '/settings/password',
];

const viewsDir = path.join(__dirname, '..', 'src', 'views');

/** Recursively find all .ejs files under a directory. */
function findEjsFiles(dir) {
  const results = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...findEjsFiles(full));
    } else if (entry.name.endsWith('.ejs')) {
      results.push(full);
    }
  }
  return results;
}

/**
 * Extract POST forms from an EJS file with their action and whether
 * they contain a _csrf hidden input.
 */
function extractPostForms(filePath) {
  const content = fs.readFileSync(filePath, 'utf8');
  const forms = [];
  const formOpenRegex = /<form\b[^>]*method=["']POST["'][^>]*>/gi;
  let match;

  while ((match = formOpenRegex.exec(content)) !== null) {
    const formTag = match[0];
    const startIndex = match.index;

    const actionMatch = formTag.match(/action=["']([^"']+)["']/);
    const action = actionMatch ? actionMatch[1] : null;

    const closeIndex = content.indexOf('</form>', startIndex);
    if (closeIndex === -1) continue;

    const formBody = content.slice(startIndex, closeIndex);
    const hasCsrf = /name=["']_csrf["']/.test(formBody);
    const line = content.slice(0, startIndex).split('\n').length;

    forms.push({ action, hasCsrf, line, file: path.relative(viewsDir, filePath) });
  }

  return forms;
}

describe('CSRF token presence in POST forms', () => {
  const ejsFiles = findEjsFiles(viewsDir);

  test('EJS templates exist', () => {
    expect(ejsFiles.length).toBeGreaterThan(0);
  });

  for (const action of CSRF_PROTECTED_ACTIONS) {
    test(`forms posting to "${action}" include _csrf token`, () => {
      const missingCsrf = [];

      for (const file of ejsFiles) {
        const forms = extractPostForms(file);
        for (const form of forms) {
          if (form.action === action && !form.hasCsrf) {
            missingCsrf.push(`${form.file}:${form.line}`);
          }
        }
      }

      if (missingCsrf.length > 0) {
        throw new Error(
          `Missing _csrf hidden input in form(s) posting to "${action}":\n` +
            missingCsrf.map((loc) => `  - ${loc}`).join('\n')
        );
      }
    });
  }

  test('no POST form to a CSRF-protected route is missing _csrf', () => {
    const allMissing = [];

    for (const file of ejsFiles) {
      const forms = extractPostForms(file);
      for (const form of forms) {
        if (!form.action) continue;
        // Strip EJS and JS template expressions to get the static route
        const cleanAction = form.action
          .replace(/<%.*?%>/g, '')
          .replace(/\$\{[^}]*\}/g, '');
        const isProtected = CSRF_PROTECTED_ACTIONS.some(
          (route) => cleanAction === route
        );
        if (isProtected && !form.hasCsrf) {
          allMissing.push(`${form.file}:${form.line} (action="${form.action}")`);
        }
      }
    }

    if (allMissing.length > 0) {
      throw new Error(
        'POST forms to CSRF-protected routes missing _csrf hidden input:\n' +
          allMissing.map((loc) => `  - ${loc}`).join('\n')
      );
    }
  });
});
