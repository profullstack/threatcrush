import { beforeEach,describe,expect,it,vi } from "vitest";
import { randomUUID } from "node:crypto";
import { fakeDb,type Row } from "../incidents/__tests__/fake-db";
const mocks=vi.hoisted(()=>({scan:vi.fn(),raise:vi.fn(),notify:vi.fn()}));
vi.mock("@/lib/github-app",async original=>({...await original<typeof import("../github-app")>(),readAppCredentials:()=>({appId:"1",privateKey:"unused"}),createAppJwt:()=>"app-jwt",createInstallationToken:async()=>({token:"installation-token"})}));
vi.mock("@/lib/github-repo-scan",()=>({scanRepository:mocks.scan}));
vi.mock("@/lib/incidents/store",()=>({upsertIncident:mocks.raise,pageable:(r:unknown)=>r}));
vi.mock("@/lib/incidents/notify",()=>({notifyIncident:mocks.notify}));
import { discoverOwner,enableOwners,githubPages,runMonitoringJob,verifyGitHubIdentity,type MonitoringOwner } from "../github-monitoring";

function db(tables:Record<string,Row[]>){
 const base=fakeDb(tables),from=base.from.bind(base);
 const wrapped={...base,from(name:string){
  const query=from(name);
  return Object.assign(query,{upsert(raw:Row|Row[],opts:{onConflict:string}){
   const values=Array.isArray(raw)?raw:[raw],keys=opts.onConflict.split(",");const ids:unknown[]=[];
   for(const value of values){const existing=(tables[name]??=[]).find(r=>keys.every(k=>r[k]===value[k]));if(existing){Object.assign(existing,value);ids.push(existing.id);}else{const row={id:randomUUID(),...value};tables[name].push(row);ids.push(row.id);}}
   return from(name).select("*").in("id",ids);
  }});
 },rpc:vi.fn()};
 return wrapped as unknown as ReturnType<typeof fakeDb>&{rpc:ReturnType<typeof vi.fn>};
}
const owner:MonitoringOwner={id:"owner-1",org_id:"org-1",installation_id:123,account_id:42,account_login:"our-org",enabled:true,silence_examples:true,silence_warnings:false,last_discovery_at:null};
const repository=(id:number)=>({id,full_name:`our-org/repo-${id}`,default_branch:"main",pushed_at:"2026-10-30T00:00:00Z"});
const json=(body:unknown,status=200)=>new Response(JSON.stringify(body),{status});
beforeEach(()=>{
 vi.mocked(fetch).mockReset();mocks.scan.mockReset();mocks.raise.mockReset();mocks.notify.mockReset();
 mocks.scan.mockResolvedValue({findings:[],truncated:false});
 mocks.raise.mockResolvedValue({page:true,incident:{id:"incident-1"}});
});

describe("GitHub identities and pagination",()=>{
 it("lists all 345 repositories over four pages",async()=>{
  const repos=Array.from({length:345},(_,i)=>repository(i));
  vi.mocked(fetch).mockImplementation(async url=>{const page=Number(new URL(String(url)).searchParams.get("page"));return json({repositories:repos.slice((page-1)*100,page*100)});});
  expect(await githubPages("/installation/repositories","token","repositories")).toHaveLength(345);
  expect(fetch).toHaveBeenCalledTimes(4);
 });
 it("propagates a failed page instead of presenting the first page as complete",async()=>{
  vi.mocked(fetch).mockResolvedValueOnce(json(Array.from({length:100},()=>({})))).mockResolvedValueOnce(json({},403));
  await expect(githubPages("/user/orgs","token")).rejects.toThrow("rate limit");
 });
 it("verifies the personal account and active org-admin roles only",async()=>{
  vi.mocked(fetch).mockResolvedValueOnce(json({id:1,login:"person"})).mockResolvedValueOnce(json([
   {role:"admin",state:"active",organization:{id:42,login:"our-org"}},
   {role:"member",state:"active",organization:{id:43,login:"not-admin"}},
   {role:"admin",state:"pending",organization:{id:44,login:"pending"}},
  ]));
  expect((await verifyGitHubIdentity("ephemeral-token")).owners.map(o=>o.login)).toEqual(["person","our-org"]);
 });
 it("refuses an unverified owner before querying installations",async()=>{
  const admin=db({github_monitoring_links:[{org_id:"org-1",allowed_owners:[{id:42}]}]});
  await expect(enableOwners(admin,"org-1",[999])).rejects.toThrow("authorize");expect(fetch).not.toHaveBeenCalled();
 });
 it("requires a GitHub installation for every requested owner",async()=>{
  const admin=db({github_monitoring_links:[{org_id:"org-1",allowed_owners:[{id:42}]}]});
  vi.mocked(fetch).mockResolvedValue(json([]));await expect(enableOwners(admin,"org-1",[42])).rejects.toThrow("Install");
 });
 it("rejects metadata-only installations instead of claiming private-code coverage",async()=>{
  const admin=db({github_monitoring_links:[{org_id:"org-1",allowed_owners:[{id:42}]}]});
  vi.mocked(fetch).mockResolvedValue(json([{id:123,account:{id:42,login:"our-org"},permissions:{metadata:"read",pull_requests:"read"},repository_selection:"all"}]));
  await expect(enableOwners(admin,"org-1",[42])).rejects.toThrow("Contents: Read");
  expect(admin.tables.github_monitoring_owners??[]).toHaveLength(0);
 });
});

describe("durable repository discovery",()=>{
 it("queues every repo beyond the old ten-repo cap and preserves existing completion/quota/lease state",async()=>{
  const repos=Array.from({length:345},(_,i)=>repository(i));
  const admin=db({github_monitoring_owners:[{...owner}],github_monitoring_repositories:[
   {id:"existing",owner_id:owner.id,repo_id:0,pushed_at:repos[0].pushed_at,status:"complete",next_scan_at:"later",last_counts:{warnings:2}},
   {id:"in-flight",owner_id:owner.id,repo_id:1,pushed_at:"old",status:"running",lease_until:"lease",next_scan_at:"later"},
   {id:"removed",owner_id:owner.id,repo_id:999,status:"complete"},
  ]});
  vi.mocked(fetch).mockImplementation(async url=>{const page=Number(new URL(String(url)).searchParams.get("page"));return json({repositories:repos.slice((page-1)*100,page*100)});});
  expect(await discoverOwner(admin,owner)).toBe(345);
  const rows=admin.tables.github_monitoring_repositories;
  expect(rows.filter(r=>r.status!=="removed")).toHaveLength(345);
  expect(rows.find(r=>r.id==="existing")).toMatchObject({status:"complete",last_counts:{warnings:2},next_scan_at:"later"});
  expect(rows.find(r=>r.id==="in-flight")).toMatchObject({status:"running",lease_until:"lease"});
  expect(rows.find(r=>r.id==="removed")?.status).toBe("removed");
  expect(admin.tables.github_monitoring_owners[0].repository_count).toBe(345);
 });
});

describe("monitoring worker and paging",()=>{
 function setup(){
  const job={id:"job-1",owner_id:owner.id,full_name:"our-org/repo",default_branch:"main",pushed_at:"old",status:"running",lease_until:"lease"};
  const admin=db({github_monitoring_owners:[{...owner}],github_monitoring_repositories:[job]});
  admin.rpc.mockResolvedValue({data:[{...job}],error:null});
  vi.mocked(fetch).mockResolvedValue(json({resources:{core:{remaining:5000,reset:2000000000}}}));
  return admin;
 }
 const finding=(severity:string,file="src/app.ts")=>({ruleId:"secret-private-key",file,line:1,severity,excerpt:"[REDACTED]"});
 it("saves warnings with example silences and does not page",async()=>{
  const admin=setup();mocks.scan.mockResolvedValue({findings:[finding("high","docs/README.md"),finding("high")],truncated:false});
  expect(await runMonitoringJob(admin)).toMatchObject({status:"complete",counts:{critical:0,silenced:1,warnings:1}});
  expect(mocks.raise).not.toHaveBeenCalled();expect(mocks.notify).not.toHaveBeenCalled();
  expect(JSON.stringify(admin.tables)).not.toContain("[REDACTED]");
 });
 it("critical docs findings bypass every mute and route to Owners + Admins, not a selected team",async()=>{
  const admin=setup();admin.tables.github_monitoring_owners[0].silence_warnings=true;
  mocks.scan.mockResolvedValue({findings:[finding("critical","docs/key.md")],truncated:false});
  expect(await runMonitoringJob(admin)).toMatchObject({counts:{critical:1}});
  expect(mocks.raise.mock.calls[0][1]).toBe(owner.org_id);expect(mocks.raise.mock.calls[0][2]).toBeNull();
  expect(mocks.notify).toHaveBeenCalledOnce();
  mocks.raise.mockResolvedValue({page:false,incident:{id:"incident-1"}});
  await runMonitoringJob(admin);expect(mocks.notify).toHaveBeenCalledOnce();
 });
 it("defers to GitHub's reset time without dropping queued work",async()=>{
  const admin=setup();vi.mocked(fetch).mockResolvedValue(json({resources:{core:{remaining:100,reset:2000000000}}}));
  expect(await runMonitoringJob(admin)).toEqual({status:"rate_limited"});expect(mocks.scan).not.toHaveBeenCalled();
  expect(admin.tables.github_monitoring_repositories[0]).toMatchObject({status:"queued",lease_until:null,next_scan_at:new Date(2000000030000).toISOString()});
 });
 it("records failures without a false clean result",async()=>{
  const admin=setup();mocks.scan.mockRejectedValue(new Error("offline"));
  expect(await runMonitoringJob(admin)).toEqual({status:"failed"});expect(admin.tables.github_monitoring_repositories[0].last_counts).toBeUndefined();
 });
 it("requeues a new push that arrives during a scan and reports scan limits",async()=>{
  const admin=setup();mocks.scan.mockImplementation(async()=>{admin.tables.github_monitoring_repositories[0].pushed_at="new";return {findings:[],truncated:true};});
  expect(await runMonitoringJob(admin)).toMatchObject({status:"queued",truncated:true});
 });
 it("does not invent work when the durable queue is empty",async()=>{
  const admin=setup();admin.rpc.mockResolvedValue({data:[],error:null});expect(await runMonitoringJob(admin)).toEqual({status:"idle"});expect(fetch).not.toHaveBeenCalled();
 });
});
