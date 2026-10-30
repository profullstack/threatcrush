import { beforeEach,describe,it,expect,vi } from "vitest";
import { NextRequest } from "next/server";
import { fakeDb } from "@/lib/incidents/__tests__/fake-db";
const state=vi.hoisted(()=>({principal:null as unknown,db:null as unknown}));
const mocks=vi.hoisted(()=>({enable:vi.fn(),link:vi.fn(),installed:vi.fn(),sync:vi.fn(),worker:vi.fn()}));
vi.mock("@/lib/access",async original=>({...await original<typeof import("@/lib/access")>(),getPrincipal:async()=>state.principal}));
vi.mock("@/lib/supabase",()=>({getSupabaseAdmin:()=>state.db}));
vi.mock("@/lib/github-monitoring",async original=>({...await original<typeof import("@/lib/github-monitoring")>(),enableOwners:mocks.enable,linkIdentity:mocks.link,installations:mocks.installed,monitoringAppAccess:async()=>({contents_read:true,permissions_url:"https://github.com/settings/apps/threatcrush/permissions"}),discoverOwner:mocks.sync,runMonitoringJob:mocks.worker}));
import {POST,GET} from "../route";
import {POST as worker} from "../worker/route";
const org="11111111-1111-4111-8111-111111111111",other="22222222-2222-4222-8222-222222222222";
const req=(body:unknown)=>new NextRequest("https://threatcrush.com/api/github/monitoring",{method:"POST",body:JSON.stringify(body)});
let db:ReturnType<typeof fakeDb>;
beforeEach(()=>{
 db=fakeDb({organization_members:[{org_id:org,user_id:"operator",role:"owner",organizations:{name:"Org",slug:"org"}}],github_monitoring_links:[{org_id:org,allowed_owners:[{id:42,login:"ours"}]}],github_monitoring_owners:[]});state.db=db;state.principal={kind:"user",userId:"operator"};
 mocks.enable.mockReset();mocks.link.mockReset();mocks.installed.mockReset();mocks.sync.mockReset();
});
describe("bulk monitoring access",()=>{
 it("requires a signed-in person",async()=>{state.principal=null;expect((await POST(req({org_id:org,action:"enable",owner_ids:[42]}))).status).toBe(401);expect((await GET(req({}))).status).toBe(401);});
 it("rejects other organizations and members changing defaults",async()=>{
  expect((await POST(req({org_id:other,action:"defaults"}))).status).toBe(403);
  db.tables.organization_members[0].role="member";expect((await POST(req({org_id:org,action:"enable",owner_ids:[42]}))).status).toBe(403);
 });
 it("filters discovery to verified owners, never another customer's installation",async()=>{
  mocks.installed.mockResolvedValue([{id:1,account:{id:42,login:"ours"},repository_selection:"all"},{id:2,account:{id:999,login:"private-customer"},repository_selection:"all"}]);
  const response=await POST(req({org_id:org,action:"discover"}));expect(response.status).toBe(200);const b=await response.json();expect(b.installations).toHaveLength(1);expect(JSON.stringify(b)).not.toContain("private-customer");
 });
 it("enables whole owners in one request, never a list of repository checkboxes",async()=>{
  expect((await POST(req({org_id:org,action:"enable",owner_ids:[42,43]}))).status).toBe(200);expect(mocks.enable).toHaveBeenCalledWith(db,org,[42,43]);
 });
 it("bulk defaults clear legacy team routing and silence examples",async()=>{
  db.tables.github_repository_policies=[{org_id:org,team_id:"old-team",silence_examples:false},{org_id:other,team_id:"other",silence_examples:false}];
  expect((await POST(req({org_id:org,action:"defaults"}))).status).toBe(200);
  expect(db.tables.github_repository_policies[0]).toMatchObject({team_id:null,silence_examples:true});expect(db.tables.github_repository_policies[1].team_id).toBe("other");
 });
 it("binds OAuth to an HttpOnly state cookie and existing ThreatCrush organization",async()=>{
  process.env.GITHUB_CLIENT_ID="client";process.env.GITHUB_CLIENT_SECRET="secret";
  const r=await POST(req({org_id:org,action:"connect"}));expect(r.status).toBe(200);const b=await r.json(),url=new URL(b.url);
  expect(url.searchParams.get("prompt")).toBe("select_account");expect(url.searchParams.get("scope")).toBe("read:user read:org");expect(url.searchParams.get("redirect_uri")).toMatch(/\/api\/auth\/callback$/);
  expect(r.headers.get("set-cookie")).toContain("HttpOnly");expect(db.tables.github_monitoring_oauth_states[0]).toMatchObject({org_id:org,user_id:"operator"});expect(JSON.stringify(db.tables)).not.toContain(url.searchParams.get("state")!);
 });
 it("does not store the optional GitHub verification token",async()=>{
  mocks.link.mockResolvedValue({user:{login:"second-account"}});const token="ephemeral-"+"x".repeat(30);
  const r=await POST(req({org_id:org,action:"connect",token}));expect(await r.json()).toEqual({connected:"second-account"});expect(JSON.stringify(db.tables)).not.toContain(token);
 });
 it("refuses unauthorized worker requests",async()=>{process.env.GITHUB_MONITOR_WORKER_KEY="worker-key";expect((await worker(req({}))).status).toBe(401);expect(mocks.worker).not.toHaveBeenCalled();});
});
