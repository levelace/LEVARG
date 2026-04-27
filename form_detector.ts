/**
 * form_detector — heuristic login-form detector.
 *
 * Given an HTML document and the URL it was served from, identify a likely
 * login form and return the selectors needed to fill it. Used in two places:
 *
 *   1. Discovery phase of the Auto-Hunter: when the crawler finds a page that
 *      looks like a login wall, log a hint suggesting the operator configure
 *      an auth-flow for the scope. The hunt does NOT auto-submit credentials
 *      from a discovery hit — auto-fill only fires from an explicitly
 *      configured auth-flow run.
 *
 *   2. Auth-flow editor UI: "auto-detect" button — fetch the configured login
 *      URL through the lab proxy, run this detector on the response, and
 *      pre-populate the step list (goto + fill[username] + fill[password] +
 *      click[submit]).
 *
 * Heuristics, ordered by signal strength:
 *   - Exactly one <input type="password"> in the document → strongest signal
 *   - The <form> ancestor of that password input is the login form
 *   - The username field is the closest preceding <input> with type
 *     email/text/tel/<absent> inside the same form
 *   - The submit field is a <button type="submit"> or <input type="submit">
 *     inside the form, or any visible button with text matching
 *     /sign in|log in|continue|next/i
 *
 * Returns null when no plausible login form is present.
 */
import * as cheerio from 'cheerio';
import type { Element as DomElement } from 'domhandler';

export interface DetectedLoginForm {
  // CSS selectors that should resolve uniquely on the page when puppeteer
  // replays the auth flow. Prefer id-based selectors when available.
  formSelector: string;
  usernameSelector: string | null;
  passwordSelector: string;
  submitSelector: string | null;
  // For diagnostics / UI display
  formAction: string | null;
  formMethod: 'GET' | 'POST';
  hasMultiStep: boolean; // true if username and password are in different forms
}

/**
 * Build a minimal-but-unique CSS selector for a node. Prefers `#id`, then
 * `name=`, then `type=` + nth-of-type, finally falling back to the tag name.
 * The selector is checked for uniqueness against the document; if not unique
 * an `nth-of-type(...)` clause is appended.
 */
function buildSelector($: cheerio.CheerioAPI, el: DomElement): string {
  const $el = $(el);
  const id = $el.attr('id');
  if (id) {
    const safeId = id.replace(/(["\\])/g, '\\$1');
    return `#${safeId}`;
  }
  const name = $el.attr('name');
  if (name) {
    const tag = (el as { tagName?: string }).tagName ?? 'input';
    return `${tag}[name="${name.replace(/"/g, '\\"')}"]`;
  }
  const type = $el.attr('type');
  const tag = (el as { tagName?: string }).tagName ?? 'input';
  if (type) {
    const sel = `${tag}[type="${type}"]`;
    if ($(sel).length === 1) return sel;
  }
  // Last-resort: nth-of-type within parent.
  const parent = $el.parent();
  const idx = parent.children(tag).index(el) + 1;
  return `${tag}:nth-of-type(${idx})`;
}

function inferUsernameField(
  $: cheerio.CheerioAPI,
  $form: cheerio.Cheerio<DomElement>,
  passwordEl: DomElement,
): DomElement | null {
  const candidates = $form
    .find('input')
    .filter((_, el) => {
      const t = ($(el).attr('type') ?? 'text').toLowerCase();
      return ['email', 'text', 'tel', 'username'].includes(t) || !$(el).attr('type');
    })
    .toArray();

  // Prefer the closest preceding candidate to the password field.
  const passwordIndex = $form.find('input').toArray().indexOf(passwordEl);
  let best: DomElement | null = null;
  let bestDistance = Number.POSITIVE_INFINITY;
  for (const c of candidates) {
    const idx = $form.find('input').toArray().indexOf(c);
    if (idx >= 0 && idx < passwordIndex && passwordIndex - idx < bestDistance) {
      best = c;
      bestDistance = passwordIndex - idx;
    }
  }
  // Fall back to the first candidate if none precede the password field.
  return best ?? candidates[0] ?? null;
}

function inferSubmitField(
  $: cheerio.CheerioAPI,
  $form: cheerio.Cheerio<DomElement>,
): DomElement | null {
  const explicit = $form.find('button[type="submit"], input[type="submit"]').get(0);
  if (explicit) return explicit;
  const labelMatch = /(sign\s*in|log\s*in|login|continue|next|submit)/i;
  const labelled = $form
    .find('button, [role="button"]')
    .filter((_, el) => labelMatch.test($(el).text()))
    .get(0);
  return labelled ?? null;
}

export function detectLoginForm(html: string, _baseUrl: string): DetectedLoginForm | null {
  const $ = cheerio.load(html);
  const passwords = $('input[type="password"]').toArray();
  if (passwords.length === 0) return null;

  // If there are multiple password inputs (e.g. signup with confirmation), the
  // first one is the authentication password by convention; later ones are
  // confirmations. We keep the first.
  const passwordEl = passwords[0];
  const $passwordEl = $(passwordEl);
  const $form = $passwordEl.closest('form');
  if ($form.length === 0) {
    // Some SPAs use no <form> at all; we still surface the password input so
    // the operator can hand-craft a flow with its selector.
    return {
      formSelector: 'body',
      usernameSelector: null,
      passwordSelector: buildSelector($, passwordEl),
      submitSelector: null,
      formAction: null,
      formMethod: 'POST',
      hasMultiStep: true,
    };
  }

  const $formEl = $form as unknown as cheerio.Cheerio<DomElement>;
  const usernameEl = inferUsernameField($, $formEl, passwordEl);
  const submitEl = inferSubmitField($, $formEl);

  // Detect "multi-step" pattern: user/password split across pages (Google,
  // Microsoft, Okta). Signal: the password input is hidden on initial load,
  // OR the username form has a `data-initial-view` style attribute hinting
  // at a wizard. We treat hidden-password as the canonical signal.
  const isPasswordHidden = ($passwordEl.attr('aria-hidden') === 'true') ||
    /display\s*:\s*none/i.test($passwordEl.attr('style') ?? '');

  return {
    formSelector: $form.attr('id')
      ? `#${$form.attr('id')}`
      : 'form:has(input[type="password"])',
    usernameSelector: usernameEl ? buildSelector($, usernameEl) : null,
    passwordSelector: buildSelector($, passwordEl),
    submitSelector: submitEl ? buildSelector($, submitEl) : null,
    formAction: $form.attr('action') ?? null,
    formMethod: (($form.attr('method') ?? 'POST').toUpperCase() === 'GET' ? 'GET' : 'POST'),
    hasMultiStep: isPasswordHidden,
  };
}
