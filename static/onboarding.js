'use strict';
const token = new URLSearchParams(location.hash.slice(1)).get('token');
history.replaceState(null, '', location.pathname);
const $ = id => document.getElementById(id);
const form = $('onboarding');
const password = $('password');
const button = $('activate');
const appUrl = $('invitation').dataset.appUrl;
let checking = false;
let submitting = false;
let uncertain = false;
$('issuer').textContent = location.host;

function error(message) {
  $('error').textContent = message;
  $('error').focus();
}
function recovery() {
  $('recovery').hidden = false;
  if (appUrl) {
    // The destination comes only from server configuration, never the invitation URL.
    $('recovery').textContent = 'Already set your password? ';
    const link = document.createElement('a');
    link.className = 'link';
    link.href = appUrl;
    link.textContent = 'Open your app to sign in';
    $('recovery').appendChild(link);
  }
}
function invalidLink() {
  form.hidden = true;
  $('account').hidden = true;
  $('title').textContent = "This invitation link can't be used";
  $('description').textContent = 'It may have expired, been replaced, or already been used. Ask your administrator for a new invitation if you have not finished setup.';
  recovery();
  $('title').focus();
}
async function loadInvitation() {
  if (checking) return;
  form.hidden = true;
  $('retry').hidden = true;
  $('error').textContent = '';
  if (!token) {
    $('title').textContent = 'Open your invitation email';
    $('description').textContent = 'Open the original link in your email to set up your account. If you reloaded this page, reopen that link. Ask your administrator for a new invitation if you cannot find it.';
    recovery();
    return;
  }
  checking = true;
  $('result').textContent = 'Checking your invitation…';
  try {
    const response = await fetch('/onboarding/details', {method: 'POST', redirect: 'error', cache: 'no-store', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({token})});
    if (response.status === 400) { invalidLink(); return; }
    if (!response.ok) throw new Error();
    const details = await response.json();
    if (typeof details.username !== 'string' || !details.username) throw new Error();
    $('username').textContent = details.username;
    $('saved-username').value = details.username;
    $('account').hidden = false;
    form.hidden = false;
    $('description').textContent = 'First choose a password for the account below. You will use it to sign in after setup.';
    password.focus();
  } catch (_) {
    $('retry').hidden = false;
    error("We couldn't check your invitation. Check your connection and try again. You can retry here without reopening the email.");
  } finally {
    checking = false;
    $('result').textContent = '';
  }
}
$('retry').addEventListener('click', loadInvitation);
$('toggle-password').addEventListener('click', () => {
  const shown = password.type === 'password';
  password.type = shown ? 'text' : 'password';
  $('toggle-password').textContent = shown ? 'Hide' : 'Show';
  $('toggle-password').setAttribute('aria-label', shown ? 'Hide password' : 'Show password');
  password.focus();
});
form.addEventListener('submit', async event => {
  event.preventDefault();
  if (submitting || form.hidden) return;
  $('error').textContent = '';
  const bytes = new TextEncoder().encode(password.value).length;
  if (password.value.length < 12 || bytes > 128) {
    password.setAttribute('aria-invalid', 'true');
    error(bytes > 128 ? 'This password is too long. Use fewer characters; accented characters and emoji take more space.' : 'Choose a password with at least 12 characters.');
    return;
  }
  password.removeAttribute('aria-invalid');
  submitting = true;
  button.setAttribute('aria-disabled', 'true');
  $('result').textContent = 'Setting up your account…';
  button.setAttribute('aria-busy', 'true');
  button.textContent = 'Setting up your account…';
  password.readOnly = true;
  password.type = 'password';
  $('toggle-password').textContent = 'Show';
  $('toggle-password').setAttribute('aria-label', 'Show password');
  $('toggle-password').disabled = true;
  try {
    const response = await fetch('/onboarding/accept', {method: 'POST', redirect: 'error', cache: 'no-store', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({token, password: password.value})});
    if (response.status === 400 && !uncertain) { invalidLink(); return; }
    if (response.status !== 204) throw new Error();
    form.reset();
    form.hidden = true;
    $('recovery').hidden = true;
    $('title').textContent = 'Your account is ready';
    $('description').textContent = 'Your password has been saved. Next, sign in with the account name below and the password you just chose.';
    $('next-step').hidden = false;
    $('next-step').textContent = appUrl ? 'Continue to your app, then choose Sign in.' : 'Open the app you were invited to and choose Sign in.';
    if (appUrl) { $('continue').href = appUrl; $('continue').hidden = false; }
    $('title').focus();
  } catch (_) {
    uncertain = true;
    error("We couldn't confirm whether setup finished. Try again here. If the account was already created, open your app and try signing in with the password you chose. If neither works, ask your administrator for help.");
    recovery();
  } finally {
    submitting = false;
    button.removeAttribute('aria-disabled');
    $('result').textContent = '';
    button.removeAttribute('aria-busy');
    button.textContent = 'Set password and activate';
    password.readOnly = false;
    $('toggle-password').disabled = false;
  }
});
loadInvitation();
