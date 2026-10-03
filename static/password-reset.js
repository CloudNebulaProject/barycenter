'use strict';
const token = new URLSearchParams(location.hash.slice(1)).get('token');
history.replaceState(null, '', location.pathname);
const form = document.getElementById('password-reset');
const result = document.getElementById('result');
if (!token) { form.hidden = true; result.textContent = 'Open the password reset link from your email.'; }
form.addEventListener('submit', async event => {
  event.preventDefault();
  const button = form.querySelector('button'); button.disabled = true;
  try {
    const response = await fetch('/password-reset/accept', {method: 'POST', redirect: 'error', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({token, password: document.getElementById('password').value})});
    if (response.status !== 204) throw new Error('Reset failed. Check your password length or request a new reset link.');
    form.reset(); form.hidden = true; result.textContent = 'Password changed. Sign in with your new password.';
  } catch (error) { result.textContent = error.message; button.disabled = false; }
});
