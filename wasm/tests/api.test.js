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
        file: 'main.vcl',
      },
      {
        severity: 'error',
        message: 'undefined variable "undefined_var"',
        line: 1,
        position: 33,
        file: 'main.vcl',
      },
      {
        severity: 'error',
        message: 'Type mismatch: req.http.X requires type STRING but NULL was assigned',
        line: 1,
        position: 31,
        rule: 'operator/assignment',
        file: 'main.vcl',
      },
    ]);
  });

  it('respects scope option', () => {
    const result = FalcoVCL.lint('return(pass);', { scope: 'recv' });
    expect(result.error).toBeUndefined();
  });

  it('returns a parse error as a structured entry in errors (not the error string)', () => {
    const result = FalcoVCL.lint('sub { invalid }');
    // Position must come from structured data, not the free-form error string.
    expect(result.error).toBeUndefined();
    expect(result.errors).toEqual([
      {
        severity: 'error',
        message: 'Unexpected token "{", expects IDENT',
        line: 1,
        position: 5,
        file: 'main.vcl',
      },
    ]);
    expect(typeof result.errors[0].line).toBe('number');
    expect(typeof result.errors[0].position).toBe('number');
  });

  it('attributes a parse error to the supplied mainFile', () => {
    const result = FalcoVCL.lint('sub { invalid }', { mainFile: 'entry.vcl' });
    expect(result.error).toBeUndefined();
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0].file).toBe('entry.vcl');
    expect(result.errors[0].position).toBe(5);
  });

  it('returns error when called without arguments', () => {
    const result = FalcoVCL.lint();
    expect(result.error).toBe('lint requires a VCL string argument');
  });
});

describe('FalcoVCL.lint include resolution', () => {
  const mainVcl = [
    'include "shared/custom";',
    '',
    'sub vcl_recv {',
    '  #FASTLY RECV',
    '  call custom_logic;',
    '}',
  ].join('\n');

  const customVcl = [
    'sub custom_logic {',
    '  set req.http.X-Custom = "1";',
    '}',
  ].join('\n');

  it('reports an undefined subroutine when the include is not supplied', () => {
    // Baseline: without the include map, the cross-file symbol is unknown.
    const result = FalcoVCL.lint(mainVcl);
    expect(result.error).toBeUndefined();
    const unresolved = result.errors.filter(e => /custom_logic/.test(e.message));
    expect(unresolved.length).toBeGreaterThan(0);
  });

  it('resolves a cross-file subroutine from the includes map', () => {
    const result = FalcoVCL.lint(mainVcl, {
      includes: { 'shared/custom': customVcl },
      mainFile: 'main.vcl',
    });
    expect(result.error).toBeUndefined();
    // The included subroutine is now known, so no "not defined" error for it.
    const unresolved = result.errors.filter(e => /custom_logic/.test(e.message));
    expect(unresolved).toEqual([]);
  });

  it('accepts include keys with an explicit .vcl suffix', () => {
    const result = FalcoVCL.lint(mainVcl, {
      includes: { 'shared/custom.vcl': customVcl },
    });
    expect(result.error).toBeUndefined();
    const unresolved = result.errors.filter(e => /custom_logic/.test(e.message));
    expect(unresolved).toEqual([]);
  });

  it('reports an error when an included module is missing from the map', () => {
    const result = FalcoVCL.lint('include "missing";\n', { includes: { 'other': customVcl } });
    expect(result.error).toBeUndefined();
    const resolveErrors = result.errors.filter(e =>
      /Failed to resolve include module/.test(e.message)
    );
    expect(resolveErrors.length).toBeGreaterThan(0);
  });

  it('resolves nested includes from the map', () => {
    const main = 'include "a";\n\nsub vcl_recv {\n  #FASTLY RECV\n  call from_a;\n}\n';
    const a = 'include "b";\n\nsub from_a {\n  call from_b;\n}\n';
    const b = 'sub from_b {\n  set req.http.X-B = "1";\n}\n';
    const result = FalcoVCL.lint(main, { includes: { a, b } });
    expect(result.error).toBeUndefined();
    const unresolved = result.errors.filter(e =>
      /(from_a|from_b)/.test(e.message)
    );
    expect(unresolved).toEqual([]);
  });

  it('exposes the parsed AST in the lint result', () => {
    const result = FalcoVCL.lint('sub vcl_recv { return(pass); }');
    expect(result.error).toBeUndefined();
    expect(result.ast).toBeDefined();
    expect(result.ast).not.toBeNull();
  });

  it('attributes a main-file error to the default main file name', () => {
    const main = 'sub vcl_recv {\n  #FASTLY RECV\n  set req.http.X-Main = undefined_main;\n}\n';
    const result = FalcoVCL.lint(main);
    expect(result.error).toBeUndefined();
    const errs = result.errors.filter(e => /undefined_main/.test(e.message));
    expect(errs.length).toBeGreaterThan(0);
    expect(errs.every(e => e.file === 'main.vcl')).toBe(true);
  });

  it('attributes a main-file error to the supplied mainFile option', () => {
    const main = 'sub vcl_recv {\n  #FASTLY RECV\n  set req.http.X-Main = undefined_main;\n}\n';
    const result = FalcoVCL.lint(main, { mainFile: 'entry.vcl' });
    expect(result.error).toBeUndefined();
    const errs = result.errors.filter(e => /undefined_main/.test(e.message));
    expect(errs.length).toBeGreaterThan(0);
    expect(errs.every(e => e.file === 'entry.vcl')).toBe(true);
  });

  it('attributes an included-file error to that include module key', () => {
    const main = [
      'include "shared/custom";',
      '',
      'sub vcl_recv {',
      '  #FASTLY RECV',
      '  call custom_logic;',
      '}',
    ].join('\n');
    const custom = [
      'sub custom_logic {',
      '  set req.http.X-Custom = undefined_in_include;',
      '}',
    ].join('\n');
    const result = FalcoVCL.lint(main, {
      includes: { 'shared/custom': custom },
      mainFile: 'main.vcl',
    });
    expect(result.error).toBeUndefined();
    const errs = result.errors.filter(e => /undefined_in_include/.test(e.message));
    expect(errs.length).toBeGreaterThan(0);
    expect(errs.every(e => e.file === 'shared/custom.vcl')).toBe(true);
  });
});
