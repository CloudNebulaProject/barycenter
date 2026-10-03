'use strict';
const token = new URLSearchParams(location.hash.slice(1)).get('token');
history.replaceState(null, '', location.pathname);
const form = document.getElementById('onboarding');
const result = document.getElementById('result');
if (!token) { form.hidden = true; result.textContent = 'Open the invitation link from your email.'; }
form.addEventListener('submit', async event => {
  event.preventDefault();
  const button = form.querySelector('button'); button.disabled = true;
  try {
    const response = await fetch('/onboarding/accept', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({token, password: document.getElementById('password').value})});
    if (!response.ok) throw new Error('Activation failed. Check your password length or request a new invitation.');
    form.reset(); form.hidden = true; result.textContent = 'Account activated. You can now sign in.';
  } catch (error) { result.textContent = error.message; button.disabled = false; }
});
