const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { test } = require('node:test');
const vm = require('node:vm');
const source = readFileSync(new URL('../static/onboarding.js', `file://${__filename}`), 'utf8');

async function page({ token = 'a'.repeat(64), username = 'alice', status = 200 } = {}) {
  const button = { disabled: false };
  let submit;
  const elements = {
    onboarding: { hidden: true, addEventListener: (_, callback) => { submit = callback; }, querySelector: () => button, reset: () => {} },
    result: { textContent: '' },
    account: { hidden: true },
    username: { textContent: '' },
    password: { value: 'a sufficiently long password' },
  };
  const requests = [];
  const history = [];
  vm.runInNewContext(source, {
    URLSearchParams,
    location: { hash: token ? `#token=${token}` : '', pathname: '/onboarding' },
    history: { replaceState: (...args) => history.push(args) },
    document: { getElementById: id => elements[id] },
    fetch: async (url, options) => {
      requests.push({ url, options });
      return url === '/onboarding/details'
        ? { ok: status === 200, json: async () => ({ username }) }
        : { status: 204 };
    },
  });
  await new Promise(resolve => setImmediate(resolve));
  return { elements, requests, history, submit: () => submit({ preventDefault() {} }) };
}

test('token-only invitation links show the server username before activation', async () => {
  const p = await page();
  assert.equal(p.elements.username.textContent, 'alice');
  assert.equal(p.elements.account.hidden, false);
  assert.equal(p.elements.onboarding.hidden, false);
  assert.equal(p.requests[0].url, '/onboarding/details');
  assert.deepEqual(JSON.parse(p.requests[0].options.body), { token: 'a'.repeat(64) });
  assert.equal(p.requests[0].options.cache, 'no-store');
  assert.equal(p.history[0][2], '/onboarding');
  await p.submit();
  assert.equal(p.requests[1].url, '/onboarding/accept');
  assert.equal(p.elements.onboarding.hidden, true);
  assert.match(p.elements.result.textContent, /Sign in with username alice and your chosen password/);
  assert.equal(p.elements.account.hidden, false);
});

test('username is rendered as text', async () => {
  const username = '<img src=x onerror=alert(1)> & alice';
  const p = await page({ username });
  assert.equal(p.elements.username.textContent, username);
  assert.equal(p.elements.username.innerHTML, undefined);
});

test('invalid invitations do not expose a username or the password form', async () => {
  const p = await page({ status: 400 });
  assert.equal(p.elements.username.textContent, '');
  assert.equal(p.elements.account.hidden, true);
  assert.equal(p.elements.onboarding.hidden, true);
  assert.match(p.elements.result.textContent, /Invalid or expired invitation/);
  assert.equal(p.requests.length, 1);
});

test('missing invitation links do not make a lookup', async () => {
  const p = await page({ token: '' });
  assert.equal(p.elements.onboarding.hidden, true);
  assert.equal(p.requests.length, 0);
  assert.match(p.elements.result.textContent, /Open the invitation link from your email/);
});
