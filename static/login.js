// Barycenter sign-in enhancements. Loaded as a module from /static/login.js.
// Everything here is optional: both forms submit without JavaScript.
// Passkey sign-in is intentionally not wired here; the password form keeps
// standard password-manager semantics (autocomplete=username/current-password).
// This file never stores passwords, tokens, or credentials.
'use strict';

const $ = (id) => document.getElementById(id);

// --- Password visibility toggle -------------------------------------------
function setupPasswordToggle() {
  const toggle = $('toggle-password');
  const password = $('password');
  if (!toggle || !password) return;

  const apply = (shown) => {
    password.type = shown ? 'text' : 'password';
    toggle.textContent = shown ? toggle.dataset.hide : toggle.dataset.show;
    toggle.setAttribute('aria-pressed', String(shown));
  };

  toggle.hidden = false;
  apply(false);
  toggle.addEventListener('click', () => {
    apply(password.type === 'password');
    password.focus({ preventScroll: true });
  });

  // Never submit a revealed password field in plain text mode.
  password.form?.addEventListener('submit', () => apply(false));
}

// --- Submit feedback --------------------------------------------------------
function setupSubmitState() {
  for (const form of document.querySelectorAll('form')) {
    form.addEventListener('submit', () => {
      const button = form.querySelector('button[type="submit"]');
      if (button) button.setAttribute('aria-busy', 'true');
    });
  }
}

// --- Focus management -------------------------------------------------------
function focusActiveField() {
  const error = $('error');
  if (error && !error.hidden && error.textContent.trim()) {
    // Let screen readers announce the alert first, then land on the field.
    const password = $('password');
    const identifier = $('identifier');
    const target = (password && !password.closest('[hidden]')) ? password : identifier;
    if (target && !target.closest('[hidden]')) target.focus({ preventScroll: true });
  }
}

setupPasswordToggle();
setupSubmitState();
focusActiveField();
