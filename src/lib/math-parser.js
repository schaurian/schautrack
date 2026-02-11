function parseAmount(input) {
  if (input === undefined || input === null) {
    return { ok: false, value: 0 };
  }

  const expr = String(input)
    .replace(/\s+/g, '')
    .replace(/,/g, '')
    .replace(/[–—−]/g, '-')
    .replace(/[x×]/gi, '*')
    .replace(/÷/g, '/')
    .trim();

  if (!expr || expr.length > 120 || !/^[0-9+\-*/().]+$/.test(expr)) {
    return { ok: false, value: 0 };
  }

  try {
    const value = safeMathEval(expr);
    if (typeof value !== 'number' || !Number.isFinite(value)) {
      return { ok: false, value: 0 };
    }
    return { ok: true, value: Math.round(value) };
  } catch (err) {
    return { ok: false, value: 0 };
  }
}

// Safe mathematical expression evaluator using recursive descent parser
function safeMathEval(expr) {
  let pos = 0;
  
  function peek() {
    return pos < expr.length ? expr[pos] : null;
  }
  
  function consume() {
    return pos < expr.length ? expr[pos++] : null;
  }
  
  function parseNumber() {
    let num = '';
    while (pos < expr.length && /[0-9.]/.test(expr[pos])) {
      num += consume();
    }
    if (num === '' || num === '.') {
      throw new Error('Invalid number');
    }
    return parseFloat(num);
  }
  
  function parseFactor() {
    let ch = peek();
    
    if (ch === '(') {
      consume(); // consume '('
      const result = parseExpression();
      if (consume() !== ')') {
        throw new Error('Missing closing parenthesis');
      }
      return result;
    }
    
    if (ch === '-') {
      consume(); // consume '-'
      return -parseFactor();
    }
    
    if (ch === '+') {
      consume(); // consume '+'
      return parseFactor();
    }
    
    if (/[0-9]/.test(ch)) {
      return parseNumber();
    }
    
    throw new Error('Unexpected character: ' + ch);
  }
  
  function parseTerm() {
    let left = parseFactor();
    
    while (pos < expr.length) {
      const op = peek();
      if (op === '*') {
        consume();
        left *= parseFactor();
      } else if (op === '/') {
        consume();
        const right = parseFactor();
        if (right === 0) {
          throw new Error('Division by zero');
        }
        left /= right;
      } else {
        break;
      }
    }
    
    return left;
  }
  
  function parseExpression() {
    let left = parseTerm();
    
    while (pos < expr.length) {
      const op = peek();
      if (op === '+') {
        consume();
        left += parseTerm();
      } else if (op === '-') {
        consume();
        left -= parseTerm();
      } else {
        break;
      }
    }
    
    return left;
  }
  
  const result = parseExpression();
  if (pos < expr.length) {
    throw new Error('Unexpected character at position ' + pos);
  }
  
  return result;
}

module.exports = {
  parseAmount,
  safeMathEval
};