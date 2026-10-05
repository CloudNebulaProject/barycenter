'use strict';
const token = new URLSearchParams(location.hash.slice(1)).get('token');
history.replaceState(null, '', location.pathname);
const form = document.getElementById('onboarding');
const result = document.getElementById('result');
const account = document.getElementById('account');
const username = document.getElementById('username');
async function loadInvitation() {
  form.hidden = true;
  if (!token) { result.textContent = 'Open the invitation link from your email.'; return; }
  result.textContent = 'Loading invitation…';
  try {
    const response = await fetch('/onboarding/details', {method: 'POST', redirect: 'error', cache: 'no-store', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({token})});
    if (!response.ok) throw new Error('Invalid or expired invitation. Request a new invitation.');
    const details = await response.json();
    username.textContent = details.username;
    account.hidden = false;
    form.hidden = false;
    result.textContent = '';
  } catch (error) { result.textContent = error.message; }
}
loadInvitation();
form.addEventListener('submit', async event => {
  event.preventDefault();
  const button = form.querySelector('button'); button.disabled = true;
  try {
    const response = await fetch('/onboarding/accept', {method: 'POST', redirect: 'error', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({token, password: document.getElementById('password').value})});
    if (response.status !== 204) throw new Error('Activation failed. Check your password length or request a new invitation.');
    form.reset(); form.hidden = true; result.textContent = 'Account activated. Sign in with username ' + username.textContent + ' and your chosen password.';
  } catch (error) { result.textContent = error.message; button.disabled = false; }
});
