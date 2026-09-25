/**
 * Runs inside the inspected page via chrome.scripting.executeScript({ func }).
 *
 * The function is serialized and injected on its own, so it must not reference
 * anything outside its body. It returns only what the checks need: http://
 * subresource URLs, form targets, and CSP/referrer <meta> values. No page
 * text, input values or cookies.
 */
export function collectPageSignals() {
  const MAX_RESOURCES = 200;
  const resources = [];
  const seen = new Set();
  const add = (url, kind) => {
    if (resources.length >= MAX_RESOURCES || typeof url !== 'string') return;
    if (!/^http:/i.test(url)) return;
    const key = `${kind} ${url}`;
    if (seen.has(key)) return;
    seen.add(key);
    resources.push({ url, kind });
  };

  for (const entry of performance.getEntriesByType('resource')) {
    add(entry.name, entry.initiatorType || 'other');
  }

  const refs = [
    ['script[src]', 'script', 'src'],
    ['link[rel~="stylesheet" i][href]', 'stylesheet', 'href'],
    ['link[rel~="icon" i][href]', 'icon', 'href'],
    ['iframe[src]', 'iframe', 'src'],
    ['frame[src]', 'iframe', 'src'],
    ['object[data]', 'object', 'data'],
    ['embed[src]', 'embed', 'src'],
    ['img', 'img', 'currentSrc'],
    ['img[src]', 'img', 'src'],
    ['audio[src], video[src]', 'media', 'src'],
    ['source[src]', 'source', 'src'],
    ['track[src]', 'track', 'src'],
  ];
  for (const [selector, kind, prop] of refs) {
    for (const el of document.querySelectorAll(selector)) add(el[prop], kind);
  }

  const resolve = (value) => {
    try {
      return new URL(value || '', document.baseURI).href;
    } catch {
      return null;
    }
  };

  const forms = [];
  for (const form of document.querySelectorAll('form')) {
    // getAttribute, not form.action: a field named "action" shadows the property.
    const hasPassword = !!form.querySelector('input[type="password" i]');
    forms.push({ action: resolve(form.getAttribute('action')), hasPassword });
    for (const button of form.querySelectorAll('[formaction]')) {
      forms.push({ action: resolve(button.getAttribute('formaction')), hasPassword });
    }
  }
  const passwordOutsideForm = [...document.querySelectorAll('input[type="password" i]')].some(
    (input) => !input.form
  );

  const metaCsp = [...document.querySelectorAll('meta[http-equiv]')]
    .filter((m) => m.getAttribute('http-equiv').toLowerCase() === 'content-security-policy')
    .map((m) => m.getAttribute('content') || '');
  const metaReferrer =
    [...document.querySelectorAll('meta[name]')].find((m) => m.getAttribute('name').toLowerCase() === 'referrer')?.getAttribute('content') ||
    null;

  return { resources, forms, passwordOutsideForm, metaCsp, metaReferrer };
}
