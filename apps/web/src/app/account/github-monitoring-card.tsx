"use client";
import { useCallback,useEffect,useState } from "react";
import { authHeaders } from "@/lib/auth-client";
import { useAuth } from "@/lib/auth-context";

type Organization={id:string;name:string;slug:string};
type Owner={id:number;login:string;type:string};
type Account={id:string;org_id:string;github_login:string;allowed_owners:Owner[]};
type Installed={id:number;account_id:number;login:string;selection:string;suspended:boolean;contents_read?:boolean};
type Monitored={id:string;org_id:string;account_id:number;account_login:string;enabled:boolean;silence_examples:boolean;silence_warnings:boolean;repository_count:number;error:string|null;last_discovery_at:string|null};
type Job={owner_id:string;status:string;truncated:boolean;last_counts:{critical:number;warnings:number;silenced:number}|null};
type Data={organizations:Organization[];accounts:Account[];owners:Monitored[];repositories:Job[];oauth_configured:boolean};
const button="rounded border border-tc-green/40 px-3 py-2 text-sm text-tc-green hover:bg-tc-green/10 disabled:opacity-40";
const field="w-full rounded border border-tc-border bg-tc-darker p-2 text-white";

export default function GitHubMonitoringCard(){
 const {signedIn,currentOrgId}=useAuth();
 const [data,setData]=useState<Data|null>(null),[orgId,setOrgId]=useState(""),[installed,setInstalled]=useState<Installed[]>([]);
 const [app,setApp]=useState<{contents_read:boolean;permissions_url:string}|null>(null);
 const [busy,setBusy]=useState(false),[error,setError]=useState<string|null>(null),[notice,setNotice]=useState<string|null>(null),[token,setToken]=useState("");
 const load=useCallback(async()=>{
  const r=await fetch("/api/github/monitoring",{headers:authHeaders(),cache:"no-store"});const d=await r.json();if(!r.ok)throw new Error(d.error||"Could not load GitHub monitoring");
  setData(d);setOrgId(old=>old||(d.organizations.some((o:Organization)=>o.id===currentOrgId)?currentOrgId:d.organizations[0]?.id)||"");
 },[currentOrgId]);
 useEffect(()=>{if(!signedIn)return;load().catch(e=>setError(e.message));const id=setInterval(()=>load().catch(()=>{}),30000);return()=>clearInterval(id);},[signedIn,load]);
 useEffect(()=>{if(!orgId)return;setInstalled([]);fetch("/api/github/monitoring",{method:"POST",headers:authHeaders({"Content-Type":"application/json"}),body:JSON.stringify({org_id:orgId,action:"discover"})}).then(async r=>{const d=await r.json();if(!r.ok)throw new Error(d.error||"Could not discover installations");setInstalled(d.installations);setApp(d.app??null);}).catch(e=>setError(e.message));},[orgId,data?.accounts.length]);
 useEffect(()=>{if(!signedIn)return;const value=new URLSearchParams(location.search).get("github");if(value==="connected")setNotice("GitHub account connected. Enable monitoring for an account or organization below.");else if(value)setError(value);if(location.hash==="#github-monitoring")document.getElementById("github-monitoring")?.scrollIntoView({block:"start"});},[signedIn,data?.accounts.length]);
 async function action(body:Record<string,unknown>){
  if(busy)return;setBusy(true);setError(null);setNotice(null);
  try{
   const r=await fetch("/api/github/monitoring",{method:"POST",headers:authHeaders({"Content-Type":"application/json"}),body:JSON.stringify({org_id:orgId,...body})});const d=await r.json();if(!r.ok)throw new Error(d.error||"Could not save monitoring settings");
   if(d.url){location.assign(d.url);return;}
   if(body.action==="connect")setToken("");
   if(body.action==="discover"){setInstalled(d.installations);setApp(d.app??null);}
   setNotice(d.message||(body.action==="connect"?`Connected @${d.connected}. Select Monitor all repositories below.`:body.action==="defaults"?"Test/docs/example warnings silenced everywhere. Critical pages route to Owners + Admins.":"Monitoring settings saved."));
   await load();
  }catch(e){setError((e as Error).message);}finally{setBusy(false);}
 }
 if(!signedIn)return null;
 const accounts=(data?.accounts??[]).filter(a=>a.org_id===orgId);
 const available=[...new Map(accounts.flatMap(a=>a.allowed_owners).map(o=>[o.id,o])).values()];
 const owners=(data?.owners??[]).filter(o=>o.org_id===orgId);
 const allInstalled=installed.filter(i=>!i.suspended&&i.contents_read!==false&&available.some(o=>o.id===i.account_id)).map(i=>i.account_id);
 return <section id="github-monitoring" className="scroll-mt-24 rounded-xl border border-tc-green/40 bg-tc-card p-4 sm:p-6 space-y-4">
  <h2 className="text-xl font-semibold text-white">GitHub accounts &amp; organizations</h2>
  <p className="text-sm text-tc-text-dim">Monitor all repositories in an account or organization with one action. New repositories are included automatically. No per-repository checkboxes, workflow edits or connection secrets.</p>
  <div className="rounded border border-tc-green/20 bg-tc-green/5 p-3 text-sm text-white">Defaults: test, documentation and example warnings silenced. <strong>Critical findings always page Owners + Admins</strong> through existing email/SMS/call preferences, with duplicate protection.</div>
  {app?.contents_read===false&&<div role="alert" className="rounded border border-amber-500/50 bg-amber-500/10 p-3 text-sm text-amber-200"><strong>GitHub App cannot read private repository code yet.</strong><p className="mt-2">Its current permissions cover metadata and pull requests only. The app owner must enable <strong>Repository permissions → Contents → Read-only</strong>, then approve the updated installation. Public scans can run; private scans remain blocked until GitHub grants access.</p><a className="mt-2 inline-block underline" href={app.permissions_url}>Open GitHub App permissions</a></div>}
  {error&&<p role="alert" className="break-words text-red-400">{error}</p>}
  {notice&&<p role="status" className="break-words text-tc-green">{notice}</p>}
  {busy&&<p role="status" className="text-tc-text-dim">Saving / discovering repositories…</p>}
  {!data?<p className="text-tc-text-dim">Loading GitHub monitoring…</p>:!data.organizations.length?<p className="text-tc-text-dim">Your account needs an organization owner or admin role to manage monitoring.</p>:<>
   <label className="block text-sm text-white">ThreatCrush organization<select className={field} value={orgId} disabled={busy} onChange={e=>setOrgId(e.target.value)}>{data.organizations.map(o=><option key={o.id} value={o.id}>{o.name}</option>)}</select></label>
   <div className="flex flex-wrap gap-2">
    <button className={button} disabled={busy||!data.oauth_configured} onClick={()=>action({action:"connect"})}>{accounts.length?"Connect another GitHub account":"Connect GitHub account"}</button>
    <button className={button} disabled={busy||!allInstalled.length} onClick={()=>action({action:"enable",owner_ids:allInstalled})}>Monitor all installed accounts &amp; orgs</button>
    <button className={button} disabled={busy} onClick={()=>action({action:"defaults"})}>Silence test/docs/example warnings everywhere</button>
   </div>
   <p className="text-xs text-tc-text-dim">Connecting GitHub keeps your CoinPay/email login. GitHub asks you to approve access once per account/organization; select <strong>All repositories</strong> on its app installation screen.</p>
   {accounts.length>0&&<p className="text-sm text-tc-text-dim">Connected GitHub identities: {accounts.map(a=>`@${a.github_login}`).join(", ")}</p>}
   {available.map(o=>{
    const monitor=owners.find(m=>m.account_id===o.id),install=installed.find(i=>i.account_id===o.id);
    const jobs=(data.repositories??[]).filter(j=>j.owner_id===monitor?.id);
    const count=(s:string)=>jobs.filter(j=>j.status===s).length;
    const critical=jobs.reduce((n,j)=>n+(j.last_counts?.critical??0),0);
    return <article key={o.id} className="space-y-3 border-t border-tc-border pt-4">
     <div className="flex flex-wrap justify-between gap-2"><h3 className="font-mono text-white break-all">{o.login} <span className="font-sans text-xs text-tc-text-dim">{o.type==="Organization"?"Organization":"Personal account"}</span></h3><span className="text-sm text-tc-green">{monitor?.enabled?`${monitor.repository_count} repositories ${install?.contents_read===false?"enrolled — code access limited":"monitored"}`:"Monitoring not enabled"}</span></div>
     {monitor&&<>
      <p className="text-sm text-tc-text-dim">{count("queued")} queued · {count("running")} scanning · {count("complete")} scanned · {count("failed")} failed · {critical} critical finding(s). {jobs.filter(j=>j.truncated).length} scans limited by scan caps.</p>
      <p className="text-xs text-tc-text-dim">Critical pages: Owners + Admins. Initial scans run in a durable queue within GitHub API limits; queued repositories have not been scanned yet.</p>
      {monitor.error&&<p className="text-sm text-red-400">{monitor.error}</p>}
      <label className="flex gap-2 text-sm text-white"><input type="checkbox" disabled={busy} checked={monitor.silence_examples} onChange={e=>action({action:"settings",owner_id:monitor.id,silence_examples:e.target.checked})}/>Silence test/docs/example warnings for every repository in {o.login}</label>
      <label className="flex gap-2 text-sm text-white"><input type="checkbox" disabled={busy} checked={monitor.silence_warnings} onChange={e=>action({action:"settings",owner_id:monitor.id,silence_warnings:e.target.checked})}/>Silence all noncritical warnings in {o.login}</label>
     </>}
     <div className="flex flex-wrap gap-2">
      {!install||install.suspended?<a className={button} href={`https://github.com/apps/threatcrush/installations/new?target_id=${o.id}`}>Install GitHub App for {o.login} — all repositories</a>:<>
       {install.contents_read===false&&<a className={button} href={o.type==="Organization"?`https://github.com/organizations/${o.login}/settings/installations/${install.id}`:`https://github.com/settings/installations/${install.id}`}>Review code access for {o.login}</a>}
       {install.selection!=="all"&&<a className={button} href={o.type==="Organization"?`https://github.com/organizations/${o.login}/settings/installations/${install.id}`:`https://github.com/settings/installations/${install.id}`}>Grant access to all repositories</a>}
       {!monitor?.enabled&&<button className={button} disabled={busy||install.contents_read===false} onClick={()=>action({action:"enable",owner_ids:[o.id]})}>Monitor all repositories in {o.login}</button>}
      </>}
      {monitor?.enabled&&<><button className={button} disabled={busy} onClick={()=>action({action:"sync",owner_id:monitor.id})}>Sync new repositories</button><button className={button} disabled={busy||!count("failed")} onClick={()=>action({action:"retry",owner_id:monitor.id})}>Retry failed scans</button><button className={button} disabled={busy} onClick={()=>action({action:"settings",owner_id:monitor.id,enabled:false})}>Pause monitoring</button></>}
     </div>
    </article>;
   })}
   <button className={button} disabled={busy} onClick={()=>action({action:"discover"})}>Refresh GitHub app access</button>
   <details className="border-t border-tc-border pt-3 text-sm text-tc-text-dim"><summary className="cursor-pointer">Connect using a GitHub token instead</summary><p className="my-2">A token with read:user and read:org verifies your GitHub identity and org admin roles. It is used once and never stored. Repository reads use the installed GitHub App&apos;s read permissions.</p><label className="block text-white">GitHub verification token<input type="password" autoComplete="off" className={field} value={token} onChange={e=>setToken(e.target.value)}/></label><button className={`${button} mt-2`} disabled={busy||!token} onClick={()=>action({action:"connect",token})}>Connect GitHub identity</button></details>
  </>}
 </section>;
}
