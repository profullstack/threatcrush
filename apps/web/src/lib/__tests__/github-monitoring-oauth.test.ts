import {beforeEach,describe,expect,it,vi} from "vitest";
import {NextRequest} from "next/server";
const state=vi.hoisted(()=>({row:null as unknown,calls:[] as string[],role:"owner",link:vi.fn()}));
vi.mock("@/lib/supabase",()=>({getSupabaseAdmin:()=>({from:()=>{
 const q={delete(){state.calls.push("delete");return q;},eq(){return q;},gt(){state.calls.push("expires");return q;},select(){return q;},maybeSingle:async()=>({data:state.row,error:null})};return q;
}})}));
vi.mock("@/lib/access",async original=>({...await original<typeof import("../access")>(),orgRoleOf:async()=>state.role}));
vi.mock("@/lib/github-monitoring",()=>({linkIdentity:state.link}));
import {githubMonitoringCallback} from "../github-monitoring-oauth";
const nonce="tcm_"+"a".repeat(43);
const request=(cookie=nonce)=>new NextRequest(`https://threatcrush.com/api/auth/callback?state=${nonce}&code=one-time-code`,{headers:{cookie:`tc_github_monitor_state=${cookie}`}});
beforeEach(()=>{state.row=null;state.calls=[];state.role="owner";state.link.mockReset();vi.mocked(fetch).mockReset();process.env.GITHUB_CLIENT_ID="id";process.env.GITHUB_CLIENT_SECRET="secret";});
describe("connecting GitHub without replacing CoinPay login",()=>{
 it("rejects browser-state mismatch before reading database or exchanging a code",async()=>{
  const r=await githubMonitoringCallback(request("forged"));expect(r.headers.get("location")).toContain("/account?github=");expect(state.calls).toEqual([]);expect(fetch).not.toHaveBeenCalled();
 });
 it("consumes only a live state, rejecting expiration/replay",async()=>{
  await githubMonitoringCallback(request());expect(state.calls).toEqual(["delete","expires"]);expect(fetch).not.toHaveBeenCalled();
 });
 it("rechecks organization admin access before linking",async()=>{
  state.row={user_id:"u1",org_id:"o1",verifier:"pkce"};state.role="member";
  await githubMonitoringCallback(request());expect(fetch).not.toHaveBeenCalled();expect(state.link).not.toHaveBeenCalled();
 });
 it("uses PKCE and links to the original user/org without returning GitHub tokens to the browser",async()=>{
  state.row={user_id:"u1",org_id:"o1",verifier:"pkce"};vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify({access_token:"ephemeral-github-token"})));
  const r=await githubMonitoringCallback(request());expect(state.link).toHaveBeenCalledWith(expect.anything(),"o1","u1","ephemeral-github-token");
  expect(r.headers.get("location")).toMatch(/account\?github=connected#github-monitoring$/);expect(r.headers.get("location")).not.toContain("token");expect(r.headers.get("set-cookie")).toContain("Max-Age=0");
  expect(JSON.parse(vi.mocked(fetch).mock.calls[0][1]?.body as string)).toMatchObject({code_verifier:"pkce",redirect_uri:"https://threatcrush.com/api/auth/callback"});
 });
});
