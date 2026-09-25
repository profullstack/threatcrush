// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest';

import { collectPageSignals } from '../src/lib/collect-page.js';
import { checkForms, checkMixedContent } from '../src/lib/page-checks.js';

function load(html, resourceEntries = []) {
  document.head.innerHTML = '';
  document.body.innerHTML = html;
  vi.spyOn(performance, 'getEntriesByType').mockImplementation((type) => (type === 'resource' ? resourceEntries : []));
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('collectPageSignals', () => {
  it('collects only http:// subresources from the DOM and Resource Timing', () => {
    load(
      `<script src="http://cdn.example/app.js"></script>
       <script src="https://cdn.example/safe.js"></script>
       <link rel="Stylesheet" href="http://cdn.example/site.css">
       <iframe src="http://widgets.example/frame"></iframe>
       <img src="http://img.example/logo.png">`,
      [
        { name: 'http://api.example/data', initiatorType: 'fetch' },
        { name: 'https://api.example/ok', initiatorType: 'fetch' },
      ]
    );

    const { resources } = collectPageSignals();

    expect(resources).toEqual(
      expect.arrayContaining([
        { url: 'http://api.example/data', kind: 'fetch' },
        { url: 'http://cdn.example/app.js', kind: 'script' },
        { url: 'http://cdn.example/site.css', kind: 'stylesheet' },
        { url: 'http://widgets.example/frame', kind: 'iframe' },
        { url: 'http://img.example/logo.png', kind: 'img' },
      ])
    );
    expect(resources.every((r) => r.url.startsWith('http:'))).toBe(true);
    expect(checkMixedContent('https://site.example/', resources).status).toBe('fail');
  });

  it('reads form targets from the attribute even when a field named "action" shadows form.action', () => {
    load(
      `<form action="http://collector.example/post"><input name="action" value="x"><input type="password"></form>
       <form><input name="q"><button formaction="http://other.example/go">Go</button></form>`
    );

    const signals = collectPageSignals();

    expect(signals.forms).toEqual([
      { action: 'http://collector.example/post', hasPassword: true },
      { action: document.baseURI, hasPassword: false },
      { action: 'http://other.example/go', hasPassword: false },
    ]);
    expect(signals.passwordOutsideForm).toBe(false);
    expect(checkForms('https://site.example/', signals).status).toBe('fail');
  });

  it('notices password inputs outside any form and CSP/referrer meta tags', () => {
    load('<input type="PASSWORD">');
    document.head.innerHTML = `<meta http-equiv="Content-Security-Policy" content="script-src 'self'">
      <meta name="Referrer" content="no-referrer">`;

    const signals = collectPageSignals();

    expect(signals.passwordOutsideForm).toBe(true);
    expect(signals.metaCsp).toEqual(["script-src 'self'"]);
    expect(signals.metaReferrer).toBe('no-referrer');
  });
});
