import React, { useCallback, useEffect, useState } from 'react';
import { PAGE_ORIGINS, scanTargetUrl } from '../../lib/page-checks.js';

const STATUS_STYLE = {
  pass: { icon: '✓', label: 'Pass', className: 'text-[#00ff41] border-[#00ff41]/40' },
  warn: { icon: '!', label: 'Warn', className: 'text-yellow-400 border-yellow-400/40' },
  fail: { icon: '✗', label: 'Fail', className: 'text-red-400 border-red-400/40' },
  na: { icon: '–', label: 'N/A', className: 'text-gray-500 border-gray-600' },
  unknown: { icon: '?', label: 'Unknown', className: 'text-gray-500 border-gray-600' },
};

function hostOf(url) {
  try {
    return new URL(url).host;
  } catch {
    return url || '';
  }
}

const API_HOST = hostOf(import.meta.env.VITE_APP_URL || 'https://threatcrush.com');

function CheckRow({ check }) {
  const style = STATUS_STYLE[check.status] || STATUS_STYLE.unknown;
  return (
    <li className="flex items-start gap-2 p-2 bg-[#111] rounded-lg border border-[#222]" data-check={check.id} data-status={check.status}>
      <span
        className={`flex-shrink-0 w-5 h-5 rounded-full border text-[11px] font-bold flex items-center justify-center ${style.className}`}
        aria-label={style.label}
        title={style.label}
      >
        {style.icon}
      </span>
      <div className="flex-1 min-w-0">
        <div className="flex justify-between gap-2">
          <span className="text-xs text-white">{check.title}</span>
          <span className={`text-[10px] uppercase font-semibold ${style.className.split(' ')[0]}`}>{style.label}</span>
        </div>
        <div className="text-[11px] text-gray-400 leading-snug">{check.detail}</div>
        {check.items && (
          <ul className="mt-1 space-y-0.5">
            {check.items.map((item) => (
              <li key={item} className="text-[10px] text-gray-500 [overflow-wrap:anywhere]">
                {item}
              </li>
            ))}
          </ul>
        )}
      </div>
    </li>
  );
}

function ServerScanResult({ result }) {
  if (result.error) return <div className="text-xs text-red-400">{result.error}</div>;
  return (
    <div className="text-xs space-y-1">
      <div className="text-gray-300">
        Grade <span className="text-white font-bold">{result.grade}</span> · Score{' '}
        <span className="text-white">{result.score}/100</span>
      </div>
      {(result.headers || []).map((h) => (
        <div key={h.name} className="flex justify-between">
          <span className="text-gray-400">{h.name}</span>
          <span className={h.present ? 'text-[#00ff41]' : 'text-yellow-400'}>{h.present ? 'present' : 'missing'}</span>
        </div>
      ))}
      {result.checks && (
        <div className="text-gray-500">
          security.txt {result.checks.security_txt ? 'found' : 'missing'} · robots.txt{' '}
          {result.checks.robots_txt ? 'found' : 'missing'}
        </div>
      )}
    </div>
  );
}

export default function PageChecks() {
  const [tabId, setTabId] = useState(null);
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [scan, setScan] = useState(null);

  const run = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [active] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!active) throw new Error('No active tab.');
      setTabId(active.id);
      setReport(await chrome.runtime.sendMessage({ type: 'PAGE_CHECKS', tabId: active.id }));
    } catch (err) {
      setError(err?.message || String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    run();
  }, [run]);

  // Re-check once the tab finishes (re)loading, e.g. after "Reload page".
  useEffect(() => {
    if (tabId == null) return undefined;
    const onUpdated = (id, info) => {
      if (id === tabId && info.status === 'complete') run();
    };
    chrome.tabs.onUpdated.addListener(onUpdated);
    return () => chrome.tabs.onUpdated.removeListener(onUpdated);
  }, [tabId, run]);

  function enableSiteAccess() {
    // Firefox only allows permission requests synchronously inside a user
    // action, so this must be the first call in the click handler.
    chrome.permissions
      .request({ origins: [...PAGE_ORIGINS] })
      .then((granted) => granted && run())
      .catch((err) => setError(err?.message || String(err)));
  }

  async function scanWithThreatCrush() {
    setScan({ running: true });
    try {
      const result = await chrome.runtime.sendMessage({ type: 'SCAN_URL', url: report.url });
      setScan({ running: false, result });
    } catch (err) {
      setScan({ running: false, result: { error: err?.message || String(err) } });
    }
  }

  if (loading && !report) {
    return <div className="flex-1 flex items-center justify-center text-xs text-gray-500">Checking this page…</div>;
  }
  if (error || report?.error) {
    return <div className="flex-1 p-4 text-xs text-red-400">{error || report.error}</div>;
  }
  if (report && !report.url) {
    // No activeTab grant and no host access, so the tab's URL is hidden from us.
    return (
      <div className="flex-1 p-4 space-y-3 text-xs text-gray-300">
        <p>ThreatCrush can't see this tab. Open the popup from the toolbar button, or allow site access.</p>
        <button
          onClick={enableSiteAccess}
          className="w-full py-1.5 bg-[#00ff41] text-black font-semibold text-xs rounded-lg hover:bg-[#00e03a]"
        >
          Enable page checks
        </button>
      </div>
    );
  }
  if (!report?.supported) {
    return (
      <div className="flex-1 p-4 text-xs text-gray-400">
        ThreatCrush checks http:// and https:// pages. Open a website and click the toolbar button again.
      </div>
    );
  }

  const { summary } = report;
  const target = scanTargetUrl(report.url);

  return (
    <div className="flex-1 overflow-y-auto px-4 py-3 space-y-3" data-testid="page-checks">
      <div className="flex items-center justify-between">
        <div className="min-w-0">
          <div className="text-[10px] uppercase text-gray-500 font-semibold tracking-wider">This page</div>
          <div className="text-sm text-white truncate">{hostOf(report.url)}</div>
        </div>
        <div className="flex gap-2 text-xs font-semibold" data-testid="summary">
          <span className="text-red-400">{summary.fail} fail</span>
          <span className="text-yellow-400">{summary.warn} warn</span>
          <span className="text-[#00ff41]">{summary.pass} pass</span>
        </div>
      </div>

      {!report.siteAccess && (
        <div className="p-2 rounded-lg border border-[#333] bg-[#111] text-[11px] text-gray-300 space-y-2">
          <p>
            Header and cookie checks need access to the sites you visit. The checks run in your browser; nothing
            about the page is sent anywhere.
          </p>
          <button
            onClick={enableSiteAccess}
            className="w-full py-1.5 bg-[#00ff41] text-black font-semibold text-xs rounded-lg hover:bg-[#00e03a]"
          >
            Enable page checks
          </button>
        </div>
      )}

      {report.siteAccess && !report.headersCaptured && (
        <div className="p-2 rounded-lg border border-[#333] bg-[#111] text-[11px] text-gray-300 space-y-2">
          <p>Response headers weren't captured for this page load.</p>
          <button
            onClick={() => chrome.tabs.reload(tabId)}
            className="w-full py-1.5 bg-[#111] border border-[#00ff41] text-[#00ff41] text-xs rounded-lg hover:bg-[#00ff41]/10"
          >
            Reload page
          </button>
        </div>
      )}

      <ul className="space-y-1.5">
        {report.checks.map((check) => (
          <CheckRow key={check.id} check={check} />
        ))}
      </ul>

      <div className="pt-2 border-t border-[#222] space-y-2">
        <button
          onClick={scanWithThreatCrush}
          disabled={scan?.running}
          className="w-full py-2 px-3 bg-[#00ff41] text-black font-semibold text-sm rounded-lg hover:bg-[#00e03a] transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {scan?.running ? 'Scanning…' : 'Scan with ThreatCrush'}
        </button>
        <p className="text-[10px] text-gray-500 break-all">
          Sends <span className="font-mono text-gray-400">{target}</span> (no query string) to {API_HOST},
          which fetches it and grades the response headers.
        </p>
        {scan?.result && (
          <div className="bg-[#111] border border-[#333] rounded-lg p-2" data-testid="server-scan">
            <ServerScanResult result={scan.result} />
          </div>
        )}
      </div>
    </div>
  );
}
