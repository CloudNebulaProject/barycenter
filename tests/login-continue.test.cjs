const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { test } = require('node:test');
const vm = require('node:vm');
const source = readFileSync(new URL('../static/login-continue.js', `file://${__filename}`), 'utf8');

function page(href) {
  const attributes = { href };
  const anchor = {
    getAttribute: key => attributes[key] ?? null,
    setAttribute: (key, value) => { attributes[key] = value; },
    removeAttribute: key => { delete attributes[key]; },
  };
  const stage = { attributes: {}, setAttribute(key, value) { this.attributes[key] = value; } };
  const navigations = [];
  const location = { href: 'https://idp.example.test/login?step=continue', origin: 'https://idp.example.test', replace: url => navigations.push(url) };
  vm.runInNewContext(source, {
    URL,
    window: { location },
    document: { getElementById: id => ({ 'continue-sign-in': anchor, 'stage-continue': stage })[id] ?? null },
  });
  return { attributes, stage, navigations };
}

test('continues once and disarms the visible link so it cannot start a second authorization', () => {
  const p = page('/authorize?client_id=rp&state=fed-state');
  assert.deepEqual(p.navigations, ['https://idp.example.test/authorize?client_id=rp&state=fed-state']);
  assert.equal(p.attributes.href, undefined);
  assert.equal(p.attributes['aria-disabled'], 'true');
  assert.equal(p.stage.attributes['aria-busy'], 'true');
});

test('leaves an untrusted target as a plain link and does not navigate', () => {
  for (const href of ['https://evil.example.test/authorize', '/login', 'https://user:pw@idp.example.test/authorize']) {
    const p = page(href);
    assert.deepEqual(p.navigations, []);
    assert.equal(p.attributes.href, href);
    assert.equal(p.attributes['aria-disabled'], undefined);
  }
});
