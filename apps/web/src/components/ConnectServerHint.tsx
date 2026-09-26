/**
 * How a server starts reporting to the dashboard. Shown wherever the cloud has
 * nothing yet because no daemon is linked.
 */
export default function ConnectServerHint({ className = "" }: { className?: string }) {
  return (
    <div className={`text-left mx-auto max-w-md ${className}`}>
      <p className="text-zinc-400 text-sm mb-2">On the server, with the ThreatCrush CLI installed:</p>
      <pre className="rounded-md bg-black/60 border border-zinc-800 px-3 py-2 text-sm font-mono text-green-400 overflow-x-auto">
{`threatcrush login
threatcrush servers link
threatcrush start`}
      </pre>
      <p className="text-zinc-600 text-xs mt-2">
        <code className="text-zinc-400">servers link</code> registers the machine in this organization (or reuses
        the entry with the same hostname). Use <code className="text-zinc-400">threatcrush restart</code> if the
        daemon was already running. It then sends heartbeats, detections, hardening
        findings and its automatic bans here.
      </p>
    </div>
  );
}
