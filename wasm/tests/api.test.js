import { describe, it, expect } from 'vitest';

const FalcoVCL = globalThis.FalcoVCL;

describe('FalcoVCL.parse', () => {
  it('parses valid VCL subroutine', () => {
    const result = FalcoVCL.parse('sub vcl_recv { return(pass); }');
    expect(result.error).toBeFalsy();
    expect(result.ast).toBeDefined();
  });

  it('parses VCL snippet without subroutine wrapper', () => {
    const result = FalcoVCL.parse('set req.http.X-Test = "value";');
    expect(result.error).toBeFalsy();
    expect(result.ast).toBeDefined();
  });

  it('returns error for invalid syntax', () => {
    const result = FalcoVCL.parse('sub { invalid }');
    expect(result.error).toBeDefined();
  });

  it('returns error when called without arguments', () => {
    const result = FalcoVCL.parse();
    expect(result.error).toContain('requires a VCL string argument');
  });
});

describe('FalcoVCL.tokenize', () => {
  it('tokenizes VCL into token stream', () => {
    const result = FalcoVCL.tokenize('set req.http.X-Test = "value";');
    expect(result.error).toBeUndefined();
    expect(result.tokens).toBeInstanceOf(Array);
    expect(result.tokens.length).toBeGreaterThan(0);
  });

  it('includes token metadata', () => {
    const result = FalcoVCL.tokenize('set x = 1;');
    expect(result.tokens[0]).toMatchObject({
      type: expect.any(String),
      literal: 'set',
      line: expect.any(Number),
      position: expect.any(Number),
      category: 'keyword',
    });
  });

  it('categorizes tokens correctly', () => {
    const result = FalcoVCL.tokenize('if (true) { return(pass); }');
    const categories = result.tokens.map(t => t.category);
    expect(categories).toContain('keyword');
    expect(categories).toContain('boolean');
    expect(categories).toContain('punctuation');
  });

  it('returns error when called without arguments', () => {
    const result = FalcoVCL.tokenize();
    expect(result.error).toContain('requires a VCL string argument');
  });
});

describe('FalcoVCL.format', () => {
  it('formats VCL with default options', () => {
    const result = FalcoVCL.format('sub vcl_recv{return(pass);}');
    expect(result.error).toBeUndefined();
    expect(result.formatted).toBe('sub vcl_recv {\n  return(pass);\n}\n');
  });

  it('respects indentWidth option', () => {
    const result = FalcoVCL.format('sub test { set x = 1; }', { indentWidth: 4 });
    expect(result.error).toBeUndefined();
    expect(result.formatted).toBe('sub test {\n    set x = 1;\n}\n');
  });

  it('respects indentStyle tab option', () => {
    const result = FalcoVCL.format('sub test { set x = 1; }', { indentStyle: 'tab', indentWidth: 1 });
    expect(result.error).toBeUndefined();
    expect(result.formatted).toBe('sub test {\n\tset x = 1;\n}\n');
  });

  it('returns error for invalid VCL', () => {
    const result = FalcoVCL.format('sub { invalid }');
    expect(result.error).toBe('Parse error: Parse Error: Unexpected token "{", expects IDENT, line: 1, position: 5');
  });

  it('returns error when called without arguments', () => {
    const result = FalcoVCL.format();
    expect(result.error).toBe('format requires a VCL string argument');
  });
});

describe('FalcoVCL.lint', () => {
  it('lints valid VCL without errors', () => {
    const result = FalcoVCL.lint('sub vcl_recv { return(pass); }');
    expect(result.error).toBeUndefined();
    expect(result.errors).toBeInstanceOf(Array);
  });

  it('detects linting issues', () => {
    // Using an undefined variable should produce a lint error
    const result = FalcoVCL.lint('sub vcl_recv { set req.http.X = undefined_var; }');
    expect(result.error).toBeUndefined();
    expect(result.errors).toEqual([
      {
        severity: 'warning',
        message: 'Subroutine "vcl_recv" is missing Fastly boilerplate comment "#FASTLY RECV" inside definition',
        line: 1,
        position: 1,
        rule: 'subroutine/boilerplate-macro',
      },
      {
        severity: 'error',
        message: 'undefined variable "undefined_var"',
        line: 1,
        position: 33,
      },
      {
        severity: 'error',
        message: 'Type mismatch: req.http.X requires type STRING but NULL was assigned',
        line: 1,
        position: 31,
        rule: 'operator/assignment',
      },
    ]);
  });

  it('respects scope option', () => {
    const result = FalcoVCL.lint('return(pass);', { scope: 'recv' });
    expect(result.error).toBeUndefined();
  });

  it('returns error when called without arguments', () => {
    const result = FalcoVCL.lint();
    expect(result.error).toBe('lint requires a VCL string argument');
  });
});
