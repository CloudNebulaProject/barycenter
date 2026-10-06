const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { test } = require('node:test');
const vm = require('node:vm');
const source = readFileSync(new URL('../static/onboarding.js', `file://${__filename}`), 'utf8');
const html = readFileSync(new URL('../static/onboarding.html', `file://${__filename}`), 'utf8');

async function page({ token = 'a'.repeat(64), username = 'alice', appUrl = 'https://notes.example.test/', details = [200], accept = [204] } = {}) {
  const elements = {};
  function element() {
    return { hidden: false, disabled: false, textContent: '', value: '', type: 'password', attributes: {}, handlers: {}, children: [],
      addEventListener(event, cb) { this.handlers[event] = cb; },
      setAttribute(key, value) { this.attributes[key] = value; },
      removeAttribute(key) { delete this.attributes[key]; },
      appendChild(child) { this.children.push(child); },
      focus() { this.focused = true; },
      reset() { elements.password.value = ''; },
    };
  }
  // Read initial visibility from the actual HTML so a stray visible CTA is caught.
  for (const tag of html.matchAll(/<[^>]+\bid="([^"]+)"[^>]*>/g)) {
    elements[tag[1]] = element();
    elements[tag[1]].hidden = /\bhidden\b/.test(tag[0]);
  }
  elements.invitation.dataset = { appUrl };
  elements.password.value = 'a sufficiently long password';
  const requests = [], history = [];
  vm.runInNewContext(source, {
    URLSearchParams, TextEncoder,
    location: { hash: token ? `#token=${token}` : '', pathname: '/onboarding', host: 'auth.example.test' },
    history: { replaceState: (...args) => history.push(args) },
    document: { getElementById: id => elements[id], createElement: () => element() },
    fetch: async (url, options) => {
      requests.push({ url, options });
      const outcomes = url === '/onboarding/details' ? details : accept;
      const outcome = outcomes.shift();
      if (outcome instanceof Error) throw outcome;
      if (typeof outcome === 'function') return outcome();
      return { status: outcome, ok: outcome === 200, json: async () => ({ username }) };
    },
  });
  await new Promise(resolve => setImmediate(resolve));
  return { elements, requests, history,
    submit: () => elements.onboarding.handlers.submit({ preventDefault() {} }),
    retry: () => elements.retry.handlers.click(),
  };
}

test('setup has no competing login and only confirmed activation exposes the app destination', async () => {
  assert.doesNotMatch(html, /href="\/login/);
  const p = await page();
  assert.equal(p.elements.username.textContent, 'alice');
  assert.equal(p.elements['saved-username'].value, 'alice');
  assert.equal(p.elements.account.hidden, false);
  assert.equal(p.elements.onboarding.hidden, false);
  assert.equal(p.elements.continue.hidden, true);
  assert.equal(p.elements.recovery.hidden, true);
  assert.deepEqual(JSON.parse(p.requests[0].options.body), { token: 'a'.repeat(64) });
  assert.equal(p.requests[0].options.cache, 'no-store');
  assert.equal(p.history[0][2], '/onboarding');
  await p.submit();
  assert.equal(p.elements.onboarding.hidden, true);
  assert.equal(p.elements.title.textContent, 'Your account is ready');
  assert.equal(p.elements.continue.hidden, false);
  assert.equal(p.elements.continue.href, 'https://notes.example.test/');
  assert.equal(p.elements.password.value, '');
  assert.equal(p.elements.title.focused, true);
});

test('no configured app gives instructions, never a bare login destination', async () => {
  const p = await page({ appUrl: '' });
  await p.submit();
  assert.equal(p.elements.continue.hidden, true);
  assert.match(p.elements['next-step'].textContent, /Open the app/);
});

test('username is rendered as text', async () => {
  const username = '<img src=x onerror=alert(1)> & alice';
  const p = await page({ username });
  assert.equal(p.elements.username.textContent, username);
  assert.equal(p.elements.username.innerHTML, undefined);
});

test('invalid and missing links never show setup or claim success', async () => {
  for (const options of [{ details: [400] }, { token: '' }]) {
    const p = await page(options);
    assert.equal(p.elements.account.hidden, true);
    assert.equal(p.elements.onboarding.hidden, true);
    assert.equal(p.elements.continue.hidden, true);
    assert.equal(p.elements.recovery.hidden, false);
    assert.equal(p.requests.length, options.token === '' ? 0 : 1);
    assert.notEqual(p.elements.title.textContent, 'Your account is ready');
  }
});

test('lookup transport and server failures can retry with the in-memory token', async () => {
  for (const failure of [new Error('offline'), 503]) {
    const p = await page({ details: [failure, 200] });
    assert.equal(p.elements.retry.hidden, false);
    assert.match(p.elements.error.textContent, /couldn't check/);
    assert.equal(p.elements.error.focused, true);
    await p.retry();
    assert.equal(p.elements.onboarding.hidden, false);
    assert.equal(p.elements.retry.hidden, true);
    assert.equal(p.requests[1].options.body, p.requests[0].options.body);
  }
});

test('uncertain activation followed by a consumed/invalid response never fabricates success', async () => {
  for (const failure of [new Error('response lost'), 500]) {
    const p = await page({ accept: [failure, 400, 204] });
    await p.submit();
    assert.match(p.elements.error.textContent, /couldn't confirm/);
    assert.equal(p.elements.activate.attributes['aria-disabled'], undefined);
    assert.equal(p.elements.continue.hidden, true);
    await p.submit();
    assert.match(p.elements.error.textContent, /couldn't confirm/);
    assert.equal(p.elements.onboarding.hidden, false);
    assert.notEqual(p.elements.title.textContent, 'Your account is ready');
    await p.submit();
    assert.equal(p.elements.title.textContent, 'Your account is ready');
    assert.equal(p.elements.recovery.hidden, true);
  }
});

test('first-attempt invalid invitation does not claim account activation', async () => {
  const p = await page({ accept: [400] });
  await p.submit();
  assert.equal(p.elements.onboarding.hidden, true);
  assert.equal(p.elements.continue.hidden, true);
  assert.match(p.elements.title.textContent, /can't be used/);
  assert.equal(p.elements.account.hidden, true);
});

test('password length checks UTF-8 maximum before sending an activation request', async () => {
  for (const value of ['short', 'é'.repeat(65)]) {
    const p = await page();
    p.elements.password.value = value;
    await p.submit();
    assert.equal(p.requests.length, 1);
    assert.equal(p.elements.password.attributes['aria-invalid'], 'true');
    assert.notEqual(p.elements.error.textContent, '');
  }
});

test('double submission sends only one activation and shows busy feedback', async () => {
  let finish;
  const p = await page({ accept: [() => new Promise(resolve => { finish = resolve; })] });
  const pending = p.submit();
  await p.submit();
  assert.equal(p.requests.length, 2);
  assert.equal(p.elements.activate.attributes['aria-disabled'], 'true');
  assert.equal(p.elements.activate.disabled, false);
  assert.equal(p.elements.activate.attributes['aria-busy'], 'true');
  finish({ status: 204 });
  await pending;
  assert.equal(p.elements.continue.hidden, false);
});
