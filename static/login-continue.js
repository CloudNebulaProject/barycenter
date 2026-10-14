// Barycenter sign-in continuation. Loaded as a module from /static/login-continue.js.
// The page is a same-origin document boundary so the browser's form-action
// policy ends at this GET instead of following a cross-origin redirect chain.
// Without JavaScript the user simply presses the Continue link.
// This file never logs, stores, or transmits the URL or any auth state.
'use strict';

const anchor = document.getElementById('continue-sign-in');

function safeTarget(href) {
  let url;
  try {
    url = new URL(href, window.location.href);
  } catch {
    return null;
  }
  if (url.origin !== window.location.origin) return null;
  if (url.pathname !== '/authorize') return null;
  if (url.username || url.password) return null;
  return url;
}

if (anchor) {
  const target = safeTarget(anchor.getAttribute('href') || '');
  if (target) {
    const stage = document.getElementById('stage-continue');
    if (stage) stage.setAttribute('aria-busy', 'true');
    // Disarm the link before leaving. Safari keeps this page visible while the
    // redirect chain runs; activating the link again would start a second
    // authorization, and a federating relying party would then receive a
    // second callback for a state its first callback already consumed.
    anchor.removeAttribute('href');
    anchor.setAttribute('aria-disabled', 'true');
    // Replace, not assign: the continuation page must not remain in history,
    // so Back returns to where the user started rather than re-running login.
    window.location.replace(target.href);
  }
}
